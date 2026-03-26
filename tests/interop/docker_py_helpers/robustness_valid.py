#!/usr/bin/env python3
"""Docker-aware Python RNS valid client for robustness testing.

Announces on stdin "ANNOUNCE" command, stays alive until "QUIT" or timeout.
Used as the valid traffic source while malformed packets are injected.
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
    parser.add_argument("--timeout", type=float, default=120.0)
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
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "rete", "robustness", "v1",
    )

    print(f"PY_VALID_DEST:{dest.hexhash}", flush=True)
    print(f"PY_VALID_IDENTITY:{identity.hexhash}", flush=True)

    def announce_on_signal():
        for line in sys.stdin:
            line = line.strip()
            if line == "ANNOUNCE":
                dest.announce()
                print("PY_VALID_ANNOUNCED", flush=True)
            elif line == "QUIT":
                break

    t = threading.Thread(target=announce_on_signal, daemon=True)
    t.start()

    # Initial announce
    dest.announce()
    print("PY_VALID_ANNOUNCED", flush=True)

    # Stay alive until told to quit or timeout
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        time.sleep(0.5)

    print("PY_VALID_DONE", flush=True)


if __name__ == "__main__":
    main()
