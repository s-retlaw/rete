#!/usr/bin/env python3
"""ESP32-C6 Python data interop — Topology B (Python RNS <-> ESP32 via bridge).

Modernized version of serial_interop.py using the bridge topology:
1. Python sends announce + encrypted data via bridge
2. ESP32 echoes encrypted data back
3. Python decrypts and verifies

This uses RNS's full stack rather than raw HDLC, giving more realistic testing.
"""

import hashlib
import os
import sys
import tempfile
import time

import RNS

from interop_helpers import InteropTest


ESP32_SEED = "rete-esp32c6-test"
APP_NAME = "rete"
ASPECTS = ["example", "v1"]


def identity_from_seed(seed_str):
    h1 = hashlib.sha256(seed_str.encode()).digest()
    h2 = hashlib.sha256(h1).digest()
    prv = h1 + h2
    id_ = RNS.Identity(create_keys=False)
    id_.load_private_key(prv)
    return id_


BRIDGE_PORT = 4283


def main():
    with InteropTest("esp32c6-py-data", default_port=0, default_timeout=30.0) as t:
        # Start serial bridge
        t.start_serial_bridge(tcp_port=BRIDGE_PORT)

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

        # Setup ESP32 destination
        esp32_id = identity_from_seed(ESP32_SEED)
        esp32_dest_hash = RNS.Destination.hash_from_name_and_identity(
            f"{APP_NAME}.{'.'.join(ASPECTS)}", esp32_id
        )
        RNS.Identity.remember(
            packet_hash=None,
            destination_hash=esp32_dest_hash,
            public_key=esp32_id.get_public_key(),
            app_data=None,
        )
        esp32_dest = RNS.Destination(
            esp32_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS
        )

        # Announce ourselves so ESP32 learns our identity
        t._log("sending announce...")
        our_dest.announce()
        time.sleep(2.0)

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
