#!/usr/bin/env python3
"""Docker-aware Python RNS path request node C.

Connects after node A has disconnected. Requests path to A's dest hash
from the Rust transport node's cache.
"""

import argparse
import os
import time

import RNS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="rnsd hostname")
    parser.add_argument("--port", type=int, default=4242)
    parser.add_argument("--target-hash", required=True, help="Hex dest hash to request path for")
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

    target_hash = bytes.fromhex(args.target_hash)

    # Should NOT have the path yet
    has_path_before = RNS.Transport.has_path(target_hash)
    print(f"PY_C_HAS_PATH_BEFORE:{has_path_before}", flush=True)

    # Request the path
    print("PY_C_REQUESTING_PATH", flush=True)
    RNS.Transport.request_path(target_hash)

    # Wait for path to appear
    deadline = time.time() + 15
    found = False
    while time.time() < deadline:
        if RNS.Transport.has_path(target_hash):
            found = True
            print("PY_C_PATH_FOUND", flush=True)
            break
        time.sleep(0.5)

    if not found:
        print("PY_C_PATH_NOT_FOUND", flush=True)

    time.sleep(1)
    print("PY_C_DONE", flush=True)


if __name__ == "__main__":
    main()
