#!/usr/bin/env python3
"""Docker-aware Python RNS proof sender node.

Announces, discovers a peer (excluding transport relay), sends DATA
with a PacketReceipt, and waits for the delivery proof to route back.
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
    parser.add_argument("--exclude-dest", default="", help="Hex dest hash to exclude")
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

    exclude_hash = bytes.fromhex(args.exclude_dest) if args.exclude_dest else None

    identity = RNS.Identity()
    dest = RNS.Destination(
        identity, RNS.Destination.IN, RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )
    dest.announce()
    print("PY_A_READY", flush=True)

    # Wait for peer's announce (relayed through Rust)
    deadline = time.time() + args.timeout
    peer_hash = None
    while time.time() < deadline:
        for h in RNS.Transport.path_table:
            if h == dest.hash:
                continue
            if exclude_hash and h == exclude_hash:
                continue
            peer_hash = h
            break
        if peer_hash:
            break
        time.sleep(0.5)

    if not peer_hash:
        print("PY_A_PEER_NOT_FOUND", flush=True)
        time.sleep(1)
        sys.exit(0)

    print(f"PY_A_PEER_FOUND:{peer_hash.hex()}", flush=True)

    peer_identity = RNS.Identity.recall(peer_hash)
    if not peer_identity:
        print("PY_A_IDENTITY_NOT_RECALLED", flush=True)
        time.sleep(1)
        sys.exit(0)

    out_dest = RNS.Destination(
        peer_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )

    packet = RNS.Packet(out_dest, b"prove this")
    receipt = packet.send()

    proof_received = threading.Event()

    def delivery_callback(receipt):
        print("PY_A_PROOF_RECEIVED", flush=True)
        proof_received.set()

    def timeout_callback(receipt):
        print("PY_A_PROOF_TIMEOUT", flush=True)

    receipt.set_delivery_callback(delivery_callback)
    receipt.set_timeout_callback(timeout_callback)
    receipt.set_timeout(15)

    print("PY_A_DATA_SENT", flush=True)

    if proof_received.wait(timeout=20):
        print("PY_A_PROOF_OK", flush=True)
    else:
        print("PY_A_PROOF_WAIT_TIMEOUT", flush=True)

    time.sleep(2)
    print("PY_A_DONE", flush=True)


if __name__ == "__main__":
    main()
