#!/usr/bin/env python3
"""ESP32-C6 Python link interop — Topology B (Python RNS <-> ESP32 via bridge).

Tests Python initiating a link to ESP32:
1. Python announces so ESP32 learns path
2. ESP32 announces so Python learns path
3. Python initiates link to ESP32
4. Link establishes
5. Python sends data over link
6. Python tears down link
"""

import os
import sys
import tempfile
import time

import RNS

from interop_helpers import InteropTest


APP_NAME = "rete"
ASPECTS = ["example", "v1"]

BRIDGE_PORT = 4281


def main():
    with InteropTest("esp32c6-py-link", default_port=0, default_timeout=30.0) as t:
        # Start serial bridge
        t.start_rust_serial_bridge(tcp_port=BRIDGE_PORT)

        # Create RNS instance
        tmpdir = tempfile.mkdtemp(prefix="rete_esp32c6_py_link_")
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

        # Create our own dest and announce so ESP32 sees us (also triggers
        # ESP32 re-announce via idle-gap mechanism)
        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)
        our_dest.announce()

        esp32_dest_hash = t.discover_esp32_path(our_dest, APP_NAME, ASPECTS)

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

        # Track link events
        link_established = [False]
        link_closed = [False]
        received_data = []

        def link_established_cb(link):
            link_established[0] = True

        def link_closed_cb(link):
            link_closed[0] = True

        def packet_callback(message, packet):
            received_data.append(message)

        # Initiate link
        t._log("initiating link to ESP32...")
        link = RNS.Link(esp32_dest)
        link.set_link_established_callback(link_established_cb)
        link.set_link_closed_callback(link_closed_cb)
        link.set_packet_callback(packet_callback)

        # Wait for link establishment
        deadline = time.time() + 15
        while time.time() < deadline and not link_established[0]:
            time.sleep(0.3)

        t.check(link_established[0], "Link established with ESP32")

        if link_established[0]:
            # Send data over link
            time.sleep(1.0)
            t._log("sending data over link...")
            data_pkt = RNS.Packet(link, b"hello-from-python")
            data_pkt.send()

            # Wait for echo
            time.sleep(3.0)
            got_echo = any(b"echo:hello-from-python" in d for d in received_data)
            t.check(got_echo, "Received echo from ESP32 over link",
                    detail=f"received {len(received_data)} packets")

            # Tear down link
            t._log("tearing down link...")
            link.teardown()
            time.sleep(2.0)
            t.check(link_closed[0] or link.status == RNS.Link.CLOSED,
                    "Link closed")

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
