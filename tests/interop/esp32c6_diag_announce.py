#!/usr/bin/env python3
"""Diagnostic: ESP32-C6 announce exchange with full packet capture (Topology B).

Uses the diagnostic serial bridge to capture and log every HDLC frame
between Python RNS and ESP32, showing:
- Whether ESP32 sends ANY announce during the test window
- Whether the first-packet re-announce mechanism works
- Full packet flow with timestamps

Usage:
    cd tests/interop
    uv run python esp32c6_diag_announce.py --serial-port /dev/ttyUSB0 --timeout 30
"""

import os
import sys
import tempfile
import time

import RNS

from interop_helpers import InteropTest


APP_NAME = "rete"
ASPECTS = ["example", "v1"]
BRIDGE_PORT = 4280


def main():
    with InteropTest("esp32c6-diag-announce", default_port=0, default_timeout=30.0) as t:
        # Start DIAGNOSTIC serial bridge (logs all packets to stderr)
        bridge = t.start_diag_serial_bridge(tcp_port=BRIDGE_PORT)

        # Create RNS instance connecting via bridge
        tmpdir = tempfile.mkdtemp(prefix="rete_esp32c6_diag_ann_")
        config_path = os.path.join(tmpdir, "config")
        with open(config_path, "w") as f:
            f.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[interfaces]
  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {BRIDGE_PORT}
    ingress_control = false
""")

        rns = RNS.Reticulum(configdir=tmpdir, loglevel=RNS.LOG_VERBOSE)
        time.sleep(1.0)

        # Create our identity and destination
        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)

        # Track received announces
        received_announces = []

        def announce_handler(destination_hash, announced_identity, app_data):
            t._log(f"ANNOUNCE received: dest={destination_hash.hex()}")
            received_announces.append({
                "dest_hash": destination_hash,
                "identity": announced_identity,
                "app_data": app_data,
                "time": time.time(),
            })

        RNS.Transport.register_announce_handler(announce_handler)

        # Step 1: Announce ourselves — this is the first packet the ESP32
        # sees, which should trigger its first-packet re-announce.
        t._log("=== Step 1: Sending Python announce (triggers ESP32 re-announce) ===")
        our_dest.announce()
        time.sleep(3.0)

        # Step 2: Check if ESP32 re-announced
        t._log(f"=== Step 2: Checking for ESP32 announce ({len(received_announces)} so far) ===")

        # Wait for ESP32 announce
        deadline = time.time() + t.timeout
        while time.time() < deadline and len(received_announces) == 0:
            time.sleep(0.5)

        t.check(len(received_announces) > 0, "Received announce from ESP32",
                detail=f"got {len(received_announces)} announces")

        if received_announces:
            ann = received_announces[0]
            got_hash = ann["identity"].hash if ann["identity"] else None
            t.check(got_hash is not None, "Announce has valid identity")

        # Dump bridge stderr for packet-level diagnostics
        t._log("=== Diagnostic bridge packet log (stderr) ===")
        if bridge.stderr:
            try:
                # Non-blocking read of available stderr
                import select as sel
                while True:
                    ready, _, _ = sel.select([bridge.stderr], [], [], 0.1)
                    if not ready:
                        break
                    data = bridge.stderr.read(4096)
                    if not data:
                        break
                    for line in data.decode(errors="replace").split("\n"):
                        if line.strip():
                            t._log(f"  [bridge] {line}")
            except Exception as e:
                t._log(f"  (could not read bridge stderr: {e})")

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
