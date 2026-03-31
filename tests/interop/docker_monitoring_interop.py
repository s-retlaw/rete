#!/usr/bin/env python3
"""Docker-isolated monitoring endpoint + Prometheus scrape test.

Topology (Docker Compose):
  rnsd:        Python rnsd transport node (TCP server on 0.0.0.0:4242)
  rust-node:   rete-linux --connect rnsd:4242 --monitoring 0.0.0.0:9100
  python-node: tcp_node.py --host rnsd --port 4242 (generates traffic)
  prometheus:  prom/prometheus scraping rust-node:9100

Assertions:
  1. Rust node initialized
  2. Python announce sent
  3. Rust received Python announce
  4. Prometheus target is UP
  5. rete_uptime_seconds metric exists in Prometheus
  6. rete_packets_received_total > 0 in Prometheus

Usage:
  cd tests/interop
  uv run python docker_monitoring_interop.py
"""

import json
import time
import urllib.request
import urllib.error

from docker_helpers import DockerTopologyTest


def query_prometheus(host_port, path):
    """Query Prometheus HTTP API and return parsed JSON."""
    url = f"http://localhost:{host_port}{path}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        return json.loads(resp.read().decode())
    except Exception:
        return None


def main():
    with DockerTopologyTest("docker-monitoring", "tcp-monitoring.yml", timeout=90) as t:
        t.start()

        # Wait for Rust node to initialize
        identity_line = t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
        t.check(identity_line is not None, "Rust node initialized")

        # Wait for Python to announce
        py_announce = t.wait_for_line("python-node", "PY_ANNOUNCE_SENT", timeout=30)
        t.check(py_announce is not None, "Python announce sent")

        # Wait for Rust to receive the announce
        rust_announce = t.wait_for_line("rust-node", "ANNOUNCE:", timeout=30)
        t.check(rust_announce is not None, "Rust received Python announce")

        # Get the mapped Prometheus port
        prom_port = t.get_host_port("prometheus", 9090)
        if prom_port is None:
            t.check(False, "Prometheus port mapped", detail="could not get host port")
            return

        # Wait for Prometheus to start and scrape at least once (~15s)
        time.sleep(20)

        # Check Prometheus targets
        targets = query_prometheus(prom_port, "/api/v1/targets")
        if targets and targets.get("status") == "success":
            active = targets.get("data", {}).get("activeTargets", [])
            up_targets = [
                tgt for tgt in active
                if tgt.get("health") == "up"
            ]
            t.check(
                len(up_targets) > 0,
                "Prometheus target is UP",
                detail=f"active={len(active)}, up={len(up_targets)}",
            )
        else:
            t.check(False, "Prometheus targets API reachable", detail=str(targets))

        # Check rete_uptime_seconds metric
        uptime_result = query_prometheus(
            prom_port, "/api/v1/query?query=rete_uptime_seconds"
        )
        if uptime_result and uptime_result.get("status") == "success":
            results = uptime_result.get("data", {}).get("result", [])
            t.check(
                len(results) > 0,
                "rete_uptime_seconds metric exists in Prometheus",
                detail=f"results={len(results)}",
            )
        else:
            t.check(False, "rete_uptime_seconds query succeeded", detail=str(uptime_result))

        # Check rete_packets_received_total > 0
        pkts_result = query_prometheus(
            prom_port, "/api/v1/query?query=rete_packets_received_total"
        )
        if pkts_result and pkts_result.get("status") == "success":
            results = pkts_result.get("data", {}).get("result", [])
            if results:
                value = float(results[0].get("value", [0, "0"])[1])
                t.check(
                    value > 0,
                    "rete_packets_received_total > 0",
                    detail=f"value={value}",
                )
            else:
                t.check(False, "rete_packets_received_total has data", detail="no results")
        else:
            t.check(False, "rete_packets_received_total query succeeded", detail=str(pkts_result))

        if t.failed > 0:
            t.dump_logs("rust-node", "Rust node")
            t.dump_logs("python-node", "Python node")
            t.dump_logs("prometheus", "Prometheus")


if __name__ == "__main__":
    main()
