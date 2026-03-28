#!/usr/bin/env python3
"""ESP32-C6 Python data interop — Topology B (Python RNS <-> ESP32 via bridge).

Modernized version of serial_interop.py using the bridge topology:
1. Python sends announce + encrypted data via bridge
2. ESP32 echoes encrypted data back
3. Python decrypts and verifies

This uses RNS's full stack rather than raw HDLC, giving more realistic testing.
"""

import os
import sys
import tempfile
import time

import RNS

from interop_helpers import InteropTest


APP_NAME = "rete"
ASPECTS = ["example", "v1"]

BRIDGE_PORT = 4283


def main():
    with InteropTest("esp32c6-py-data", default_port=0, default_timeout=30.0) as t:
        # Start serial bridge
        t.start_rust_serial_bridge(tcp_port=BRIDGE_PORT)

        # Create RNS instance
        tmpdir = tempfile.mkdtemp(prefix="rete_esp32c6_py_data_")
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

        # Track received packets
        received_packets = []

        def packet_callback(data, packet):
            received_packets.append(data)

        our_dest.set_packet_callback(packet_callback)

        # Announce ourselves so ESP32 learns our identity (also triggers
        # ESP32 re-announce via idle-gap mechanism)
        t._log("sending announce...")
        our_dest.announce()

        # Wait for ESP32 announce — discover dynamically from path_table
        # since ESP32 generates a random identity on each boot.
        # Filter by matching APP_NAME/ASPECTS to avoid picking up the
        # secondary destination (rete/test/secondary) registered by the
        # ESP32 firmware for multi-dest testing.
        t._log("waiting for ESP32 announce (path discovery)...")
        esp32_dest_hash = None
        deadline = time.time() + t.timeout
        while time.time() < deadline:
            for h in list(RNS.Transport.path_table):
                if h == our_dest.hash:
                    continue
                recalled = RNS.Identity.recall(h)
                if recalled:
                    candidate = RNS.Destination(recalled, RNS.Destination.OUT,
                                                RNS.Destination.SINGLE, APP_NAME, *ASPECTS)
                    if candidate.hash == h:
                        esp32_dest_hash = h
                        break
            if esp32_dest_hash:
                break
            time.sleep(0.5)

        if esp32_dest_hash is None:
            t.check(False, "ESP32 path discovered via announce")
            RNS.Reticulum.exit_handler()
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
            return

        t._log(f"discovered ESP32 dest hash: {esp32_dest_hash.hex()}")
        esp32_id = RNS.Identity.recall(esp32_dest_hash)
        esp32_dest = RNS.Destination(
            esp32_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS
        )

        # Send encrypted DATA
        ts = int(time.time())
        ping_msg = f"ping:{ts}".encode()
        t._log(f"sending encrypted DATA: ping:{ts}")
        pkt = RNS.Packet(esp32_dest, ping_msg)
        pkt.send()

        # Wait for echo
        deadline = time.time() + t.timeout
        while time.time() < deadline and len(received_packets) == 0:
            time.sleep(0.3)

        t.check(len(received_packets) > 0, "Received response from ESP32",
                detail=f"got {len(received_packets)} packets")

        if received_packets:
            echo_data = received_packets[0]
            expected = f"echo:ping:{ts}".encode()
            t.check(echo_data == expected, "Echo matches expected payload",
                    detail=f"expected={expected!r}, got={echo_data!r}")

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
