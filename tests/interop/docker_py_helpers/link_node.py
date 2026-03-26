#!/usr/bin/env python3
"""Docker-aware Python RNS Link client node.

Discovers a peer, establishes a Link, sends data over the link,
and performs teardown.
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

    link_established = threading.Event()
    link_closed = threading.Event()
    active_link = [None]

    def link_established_cb(link):
        print(f"PY_LINK_ESTABLISHED:{link.link_id.hex()}", flush=True)
        active_link[0] = link
        link_established.set()

    def link_closed_cb(link):
        print(f"PY_LINK_CLOSED:{link.link_id.hex()}", flush=True)
        link_closed.set()

    py_identity = RNS.Identity()
    py_dest = RNS.Destination(
        py_identity,
        RNS.Destination.IN,
        RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )

    def inbound_link_established(link):
        print(f"PY_INBOUND_LINK_ESTABLISHED:{link.link_id.hex()}", flush=True)
        active_link[0] = link
        link.set_link_closed_callback(link_closed_cb)
        def link_packet_cb(data, packet):
            text = data.decode("utf-8", errors="replace")
            print(f"PY_LINK_DATA_RECEIVED:{text}", flush=True)
        link.set_packet_callback(link_packet_cb)
        link_established.set()

    py_dest.set_link_established_callback(inbound_link_established)
    py_dest.announce()

    print(f"PY_DEST_HASH:{py_dest.hexhash}", flush=True)
    print(f"PY_IDENTITY_HASH:{py_identity.hexhash}", flush=True)
    print("PY_ANNOUNCE_SENT", flush=True)

    # Wait for Rust announce
    deadline = time.time() + args.timeout
    rust_dest_hash = None
    while time.time() < deadline:
        for h in RNS.Transport.path_table:
            if h != py_dest.hash:
                rust_dest_hash = h
                print(f"PY_DISCOVERED:{h.hex()}", flush=True)
                break
        if rust_dest_hash:
            break
        time.sleep(0.5)

    if not rust_dest_hash:
        print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
        if link_established.wait(timeout=10):
            print("PY_INBOUND_LINK_OK", flush=True)
        else:
            print("PY_FAIL:no_link_established", flush=True)
            sys.exit(1)

    if rust_dest_hash:
        rust_identity = RNS.Identity.recall(rust_dest_hash)
        if rust_identity:
            rust_dest = RNS.Destination(
                rust_identity,
                RNS.Destination.OUT,
                RNS.Destination.SINGLE,
                "rete", "example", "v1",
            )
            print(f"PY_RUST_DEST_HASH:{rust_dest.hexhash}", flush=True)
            print("PY_INITIATING_LINK", flush=True)
            link = RNS.Link(rust_dest, established_callback=link_established_cb,
                            closed_callback=link_closed_cb)

            if not link_established.wait(timeout=15):
                print(f"PY_LINK_TIMEOUT:status={link.status}", flush=True)
            else:
                print("PY_LINK_ACTIVE", flush=True)
                pkt = RNS.Packet(link, b"hello via link from python")
                pkt.send()
                print("PY_LINK_DATA_SENT", flush=True)
                time.sleep(3)
                link.teardown()
                print("PY_LINK_TEARDOWN_SENT", flush=True)
                time.sleep(2)
        else:
            print("PY_FAIL:identity_not_recalled", flush=True)

    print("PY_DONE", flush=True)


if __name__ == "__main__":
    main()
