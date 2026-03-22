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
        bridge = t.start_rust_serial_bridge(tcp_port=BRIDGE_PORT)

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

        # Compute ESP32 identity and dest hash (do NOT pre-register — let
        # the announce discovery prove the full path works).
        esp32_id = identity_from_seed(ESP32_SEED)
        esp32_dest_hash = RNS.Destination.hash_from_name_and_identity(
            f"{APP_NAME}.{'.'.join(ASPECTS)}", esp32_id
        )

        # Create our identity and destination
        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)

        # Announce ourselves — this is the first packet the ESP32 sees,
        # triggering its idle-gap re-announce mechanism.
        t._log("sending Python announce...")
        our_dest.announce()

        # Wait for ESP32 announce to create a path entry
        t._log("waiting for ESP32 announce (path discovery)...")
        deadline = time.time() + t.timeout
        while time.time() < deadline:
            if RNS.Transport.has_path(esp32_dest_hash):
                break
            time.sleep(0.5)

        path_found = RNS.Transport.has_path(esp32_dest_hash)
        t.check(path_found, "ESP32 path discovered via announce")

        # Verify the identity was learned from the announce
        recalled = RNS.Identity.recall(esp32_dest_hash)
        t.check(recalled is not None, "ESP32 identity recalled from announce")

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
