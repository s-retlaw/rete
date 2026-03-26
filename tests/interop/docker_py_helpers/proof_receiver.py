#!/usr/bin/env python3
"""Docker-aware Python RNS proof receiver node.

Announces with PROVE_ALL strategy, receives DATA, and automatically
generates a delivery proof that routes back to the sender.
"""

import argparse
import os
import sys
import threading
import time

import RNS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="rnsd hostname")
    parser.add_argument("--port", type=int, default=4242)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    config_dir = "/tmp/rns_config"
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config"), "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = {args.host}
    target_port = {args.port}
    ingress_control = false
""")

    reticulum = RNS.Reticulum(configdir=config_dir)

    data_received = threading.Event()

    def packet_callback(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_B_DATA_RECEIVED:{text}", flush=True)
        data_received.set()

    identity = RNS.Identity()
    dest = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )
    dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
    dest.set_packet_callback(packet_callback)
    dest.announce()

    print(f"PY_B_DEST_HASH:{dest.hexhash}", flush=True)
    print("PY_B_PROVE_ALL_SET", flush=True)

    if data_received.wait(timeout=args.timeout):
        print("PY_B_DATA_OK", flush=True)
    else:
        print("PY_B_DATA_TIMEOUT", flush=True)

    # Keep alive for proof to propagate back
    time.sleep(5)
    print("PY_B_DONE", flush=True)


if __name__ == "__main__":
    main()
