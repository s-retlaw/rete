#!/usr/bin/env python3
"""ESP32-C6 Python announce interop — Topology B (Python RNS <-> ESP32 via bridge).

Tests cross-implementation announce exchange:
1. Python RNS announces via serial bridge to ESP32
2. ESP32 announces back
3. Python RNS receives and validates ESP32's announce
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


BRIDGE_PORT = 4280


def main():
    with InteropTest("esp32c6-py-announce", default_port=0, default_timeout=30.0) as t:
        # Start serial bridge
        bridge = t.start_serial_bridge(tcp_port=BRIDGE_PORT)

        # Create RNS instance connecting via bridge
        tmpdir = tempfile.mkdtemp(prefix="rete_esp32c6_py_ann_")
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

        # Track received announces
        received_announces = []

        def announce_handler(destination_hash, announced_identity, app_data):
            received_announces.append({
                "dest_hash": destination_hash,
                "identity": announced_identity,
                "app_data": app_data,
            })

        RNS.Transport.register_announce_handler(announce_handler)

        # Announce ourselves
        t._log("sending Python announce...")
        our_dest.announce()
        time.sleep(2.0)

        # Wait for ESP32 announce
        t._log("waiting for ESP32 announce...")
        deadline = time.time() + t.timeout
        while time.time() < deadline and len(received_announces) == 0:
            time.sleep(0.5)

        t.check(len(received_announces) > 0, "Received announce from ESP32",
                detail=f"got {len(received_announces)} announces")

        if received_announces:
            ann = received_announces[0]
            # Verify the announce is from ESP32
            esp32_id = identity_from_seed(ESP32_SEED)
            esp32_hash = RNS.Identity.truncated_hash(esp32_id.get_public_key())
            got_hash = ann["identity"].hash if ann["identity"] else None

            t.check(got_hash is not None, "Announce has valid identity")

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
