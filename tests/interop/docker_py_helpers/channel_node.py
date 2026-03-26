#!/usr/bin/env python3
"""Docker-aware Python RNS Channel client node.

Discovers a peer, establishes a Link, sends Channel messages, and tears down.
"""

import argparse
import os
import sys
import threading
import time

import RNS
import RNS.Channel


class TestMessage(RNS.Channel.MessageBase):
    MSGTYPE = 0x0100
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw


class TestMessage2(RNS.Channel.MessageBase):
    MSGTYPE = 0x0200
    def __init__(self):
        self.data = b""
    def pack(self):
        return self.data
    def unpack(self, raw):
        self.data = raw


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
    active_link = [None]

    def link_established_cb(link):
        print(f"PY_LINK_ESTABLISHED:{link.link_id.hex()}", flush=True)
        active_link[0] = link
        link_established.set()

    def link_closed_cb(link):
        print(f"PY_LINK_CLOSED:{link.link_id.hex()}", flush=True)

    # Wait for Rust announce
    deadline = time.time() + args.timeout
    rust_dest_hash = None
    while time.time() < deadline:
        for h in RNS.Transport.path_table:
            rust_dest_hash = h
            break
        if rust_dest_hash:
            break
        time.sleep(0.5)

    if not rust_dest_hash:
        print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
        sys.exit(1)

    rust_identity = RNS.Identity.recall(rust_dest_hash)
    if not rust_identity:
        print("PY_FAIL:identity_not_recalled", flush=True)
        sys.exit(1)

    rust_dest = RNS.Destination(
        rust_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "rete", "example", "v1",
    )

    link = RNS.Link(rust_dest, established_callback=link_established_cb,
                     closed_callback=link_closed_cb)

    if not link_established.wait(timeout=15):
        print(f"PY_LINK_TIMEOUT:status={link.status}", flush=True)
        sys.exit(1)

    print("PY_LINK_ACTIVE", flush=True)

    channel = link.get_channel()
    channel.register_message_type(TestMessage)
    channel.register_message_type(TestMessage2)

    msg1 = TestMessage()
    msg1.data = b"channel msg from python"
    channel.send(msg1)
    print("PY_CHANNEL_MSG1_SENT:0x0100", flush=True)
    time.sleep(3)

    msg2 = TestMessage2()
    msg2.data = b"second channel message"
    channel.send(msg2)
    print("PY_CHANNEL_MSG2_SENT:0x0200", flush=True)
    time.sleep(3)

    link.teardown()
    print("PY_LINK_TEARDOWN_SENT", flush=True)
    time.sleep(2)

    print("PY_DONE", flush=True)


if __name__ == "__main__":
    main()
