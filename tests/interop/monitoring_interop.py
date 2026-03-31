#!/usr/bin/env python3
"""Monitoring HTTP endpoint interop test.

Tests that the Rust rete node exposes a working HTTP monitoring endpoint
when started with --monitoring <addr>.

Endpoints tested:
  GET /health  -> 200, {"status":"ok"}
  GET /stats   -> 200, JSON with identity_hash, uptime_secs, transport
  GET /metrics -> 200, Prometheus text format with rete_packets_received_total
  GET /bogus   -> 404

Usage:
  cd tests/interop
  uv run python monitoring_interop.py --rust-binary ../../target/debug/rete-linux
"""

import json
import time
import urllib.request
import urllib.error

from interop_helpers import InteropTest


def main():
    with InteropTest("monitoring", default_port=4260) as t:
        # Pick a monitoring port that won't conflict
        monitor_port = t.port + 900  # e.g. 5160

        t.start_rnsd()

        # Start Python helper that announces (to generate traffic)
        py = t.start_py_helper(f"""\
import RNS
import time
import os

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(t.port)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

dest.announce()
print("PY_ANNOUNCE_SENT", flush=True)

# Keep alive long enough for the test
time.sleep({t.timeout})
""")

        # Start Rust node with monitoring enabled
        rust = t.start_rust(
            extra_args=["--monitoring", f"127.0.0.1:{monitor_port}"],
        )

        # Wait for Rust node to initialize
        identity = t.wait_for_line(rust, "IDENTITY:")
        t.check(identity is not None, "Rust node initialized")
        if identity is None:
            return

        # Wait for Python announce to arrive at Rust
        announce = t.wait_for_line(rust, "ANNOUNCE:")
        t.check(announce is not None, "Rust received Python announce")

        # Wait a few seconds for a tick to publish stats (ticks every 5s)
        time.sleep(8)

        # --- Test /health endpoint ---
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{monitor_port}/health", timeout=5
            )
            health_status = resp.getcode()
            health_body = json.loads(resp.read().decode())
            t.check(health_status == 200, "/health returns 200")
            t.check(
                health_body.get("status") == "ok",
                "/health body has status=ok",
                detail=f"got: {health_body}",
            )
        except Exception as e:
            t.check(False, "/health endpoint accessible", detail=str(e))

        # --- Test /stats endpoint ---
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{monitor_port}/stats", timeout=5
            )
            stats_status = resp.getcode()
            stats_body = json.loads(resp.read().decode())
            t.check(stats_status == 200, "/stats returns 200")
            t.check(
                "identity_hash" in stats_body,
                "/stats has identity_hash",
                detail=f"keys: {list(stats_body.keys())}",
            )
            t.check(
                "uptime_secs" in stats_body,
                "/stats has uptime_secs",
            )
            t.check(
                "transport" in stats_body,
                "/stats has transport",
            )
            t.check(
                stats_body["transport"].get("packets_received", 0) > 0,
                "/stats shows packets_received > 0",
                detail=f"packets_received={stats_body['transport'].get('packets_received')}",
            )
        except Exception as e:
            t.check(False, "/stats endpoint accessible", detail=str(e))

        # --- Test /metrics endpoint ---
        try:
            resp = urllib.request.urlopen(
                f"http://127.0.0.1:{monitor_port}/metrics", timeout=5
            )
            metrics_status = resp.getcode()
            metrics_body = resp.read().decode()
            t.check(metrics_status == 200, "/metrics returns 200")
            t.check(
                "rete_packets_received_total" in metrics_body,
                "/metrics contains rete_packets_received_total",
            )
            t.check(
                "rete_uptime_seconds" in metrics_body,
                "/metrics contains rete_uptime_seconds",
            )
            t.check(
                "rete_node_info" in metrics_body,
                "/metrics contains rete_node_info",
            )
            # Check packets_received_total > 0
            for line in metrics_body.split("\n"):
                if line.startswith("rete_packets_received_total"):
                    val = int(line.split()[-1])
                    t.check(
                        val > 0,
                        "/metrics packets_received_total > 0",
                        detail=f"value={val}",
                    )
                    break
            else:
                t.check(False, "/metrics packets_received_total line found")
        except Exception as e:
            t.check(False, "/metrics endpoint accessible", detail=str(e))

        # --- Test 404 for unknown path ---
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{monitor_port}/nonexistent", timeout=5
            )
            t.check(False, "/nonexistent returns 404 (got 200)")
        except urllib.error.HTTPError as e:
            t.check(e.code == 404, "/nonexistent returns 404", detail=f"got: {e.code}")
        except Exception as e:
            t.check(False, "/nonexistent endpoint accessible", detail=str(e))

        if t.failed > 0:
            t.dump_output("rust stdout", rust)


if __name__ == "__main__":
    main()
