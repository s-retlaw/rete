#!/usr/bin/env python3
"""Docker-aware Python RNS relay/transport relay node.

Announces, discovers a peer (excluding transport relay), sends DATA,
and waits for DATA from peer. Used for transport_relay and proof_routing tests.
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
    parser.add_argument("--label", default="NODE", help="Label prefix for output markers")
    parser.add_argument("--send-msg", default="hello", help="DATA to send to peer")
    parser.add_argument("--exclude-dest", default="", help="Hex dest hash to exclude")
    parser.add_argument("--re-announce-interval", type=float, default=5.0,
                        help="Re-announce every N seconds while searching for peer")
    args = parser.parse_args()

    label = args.label.upper()

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

    data_received = threading.Event()
    received_text = [None]

    def packet_callback(data, packet):
        text = data.decode("utf-8", errors="replace")
        received_text[0] = text
        print(f"{label}_DATA_RECEIVED:{text}", flush=True)
        data_received.set()

    identity = RNS.Identity()
    dest = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )
    dest.set_packet_callback(packet_callback)

    print(f"{label}_DEST_HASH:{dest.hexhash}", flush=True)
    print(f"{label}_IDENTITY_HASH:{identity.hexhash}", flush=True)

    # Announce
    dest.announce()
    print(f"{label}_ANNOUNCE_SENT", flush=True)

    # Wait for peer announce (skip own hash and transport relay)
    deadline = time.time() + args.timeout
    peer_dest_hash = None
    last_announce = time.time()

    while time.time() < deadline:
        known = RNS.Transport.path_table
        for h in known:
            if h == dest.hash:
                continue
            if exclude_hash and h == exclude_hash:
                continue
            peer_dest_hash = h
            print(f"{label}_DISCOVERED:{h.hex()}", flush=True)
            break
        if peer_dest_hash:
            break
        if time.time() - last_announce > args.re_announce_interval:
            dest.announce()
            last_announce = time.time()
        time.sleep(0.5)

    if peer_dest_hash:
        print(f"{label}_PEER_FOUND", flush=True)

        peer_identity = RNS.Identity.recall(peer_dest_hash)
        if peer_identity:
            out_dest = RNS.Destination(
                peer_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "rete", "example", "v1",
            )
            pkt = RNS.Packet(out_dest, args.send_msg.encode("utf-8"))
            pkt.send()
            print(f"{label}_DATA_SENT", flush=True)
        else:
            print(f"{label}_DATA_SEND_FAIL:identity_not_recalled", flush=True)

        if data_received.wait(timeout=15):
            print(f"{label}_DATA_RECV_OK", flush=True)
        else:
            print(f"{label}_DATA_RECV_FAIL:timeout", flush=True)
    else:
        print(f"{label}_PEER_NOT_FOUND", flush=True)

    time.sleep(2)
    print(f"{label}_DONE", flush=True)


if __name__ == "__main__":
    main()
