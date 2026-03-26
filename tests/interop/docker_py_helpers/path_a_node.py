#!/usr/bin/env python3
"""Docker-aware Python RNS path request node A.

Connects, announces, reports dest hash, sleeps briefly, then exits.
Rust transport node should cache the announce.
"""

import argparse
import os
import time

import RNS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="rnsd hostname")
    parser.add_argument("--port", type=int, default=4242)
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
    identity = RNS.Identity()
    dest = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )
    dest.announce()
    print(f"PY_A_DEST_HASH:{dest.hexhash}", flush=True)
    # Keep alive long enough for Rust to receive and cache the announce
    time.sleep(5)
    print("PY_A_DONE", flush=True)


if __name__ == "__main__":
    main()
