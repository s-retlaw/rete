#!/usr/bin/env python3
"""Docker-aware Python RNS TCP client node.

Generic node that announces, discovers a peer, exchanges DATA, and supports
auto-reply detection. Covers live_interop and relay_interop use cases.

Outputs structured PY_* markers for the test orchestrator.
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
    parser.add_argument("--port", type=int, default=4242, help="rnsd port")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--send-msg", default="hello from python",
                        help="DATA message to send to discovered peer")
    parser.add_argument("--exclude-dest", default="",
                        help="Hex dest hash to exclude from discovery (e.g. transport relay)")
    parser.add_argument("--ifac-netname", default="",
                        help="Optional IFAC network name")
    parser.add_argument("--auto-reply-msg", default="",
                        help="If set, register an auto-reply with this text")
    args = parser.parse_args()

    config_dir = "/tmp/rns_config"
    os.makedirs(config_dir, exist_ok=True)

    ifac_line = ""
    if args.ifac_netname:
        ifac_line = f"\n    networkname = {args.ifac_netname}"

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
    ingress_control = false{ifac_line}
""")

    reticulum = RNS.Reticulum(configdir=config_dir)

    exclude_hash = bytes.fromhex(args.exclude_dest) if args.exclude_dest else None

    data_received = threading.Event()

    def packet_callback(data, packet):
        text = data.decode("utf-8", errors="replace")
        print(f"PY_DATA_RECEIVED:{text}", flush=True)
        data_received.set()

    identity = RNS.Identity()
    dest = RNS.Destination(
        identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )
    dest.set_packet_callback(packet_callback)

    print(f"PY_DEST_HASH:{dest.hexhash}", flush=True)
    print(f"PY_IDENTITY_HASH:{identity.hexhash}", flush=True)

    dest.announce()
    print("PY_ANNOUNCE_SENT", flush=True)

    # Wait for peer announce
    deadline = time.time() + args.timeout
    peer_dest_hash = None

    while time.time() < deadline:
        known = RNS.Transport.path_table
        for h in known:
            if h == dest.hash:
                continue
            if exclude_hash and h == exclude_hash:
                continue
            peer_dest_hash = h
            print(f"PY_DISCOVERED:{h.hex()}", flush=True)
            break
        if peer_dest_hash:
            break
        time.sleep(0.5)

    if peer_dest_hash:
        print("PY_INTEROP_OK", flush=True)

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
            print("PY_DATA_SENT", flush=True)
        else:
            print("PY_DATA_SEND_FAIL:identity_not_recalled", flush=True)

        if data_received.wait(timeout=15):
            print("PY_DATA_RECV_OK", flush=True)
        else:
            print("PY_DATA_RECV_FAIL:timeout", flush=True)
    else:
        print("PY_INTEROP_FAIL:timeout_waiting_for_rust_announce", flush=True)

    time.sleep(2)
    print("PY_DONE", flush=True)


if __name__ == "__main__":
    main()
