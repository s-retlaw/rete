#!/usr/bin/env python3
"""Docker-aware Python RNS Resource transfer node.

Discovers a peer, establishes a Link, sends a Resource to Rust,
then receives Resources from Rust (ACCEPT_ALL and ACCEPT_APP phases).
"""

import argparse
import os
import sys
import threading
import time

import RNS


def ts():
    return f"[{time.time():.3f}]"


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

    link_established = threading.Event()
    link_closed = threading.Event()
    active_link = [None]
    resource_received_accept_all = threading.Event()
    resource_received_accept_app = threading.Event()
    received_resource_data_all = [None]
    received_resource_data_app = [None]
    adv_callback_invoked = [False]
    phase = ["accept_all"]

    def link_established_cb(link):
        print(f"{ts()} PY_LINK_ESTABLISHED:{link.link_id.hex()} rtt={link.rtt:.6f}", flush=True)
        active_link[0] = link
        link_established.set()

    def link_closed_cb(link):
        print(f"{ts()} PY_LINK_CLOSED:{link.link_id.hex()} status={link.status}", flush=True)
        link_closed.set()

    def resource_started_cb(resource):
        print(f"{ts()} PY_RESOURCE_STARTED:{resource.hash.hex()}:{resource.total_size}", flush=True)

    def resource_concluded_cb(resource):
        data = b""
        try:
            status_name = {0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}.get(
                resource.status, f"status={resource.status}")
            print(f"{ts()} PY_RESOURCE_CONCLUDED:{resource.hash.hex()}:{status_name}", flush=True)
            if resource.status == 0x06:
                if hasattr(resource, 'storagepath') and os.path.isfile(resource.storagepath):
                    with open(resource.storagepath, "rb") as fh:
                        data = fh.read()
                elif hasattr(resource, 'data') and resource.data is not None:
                    if hasattr(resource.data, 'read'):
                        data = resource.data.read()
                        resource.data.close()
                    elif isinstance(resource.data, (bytes, bytearray)):
                        data = resource.data
                text = data.decode("utf-8", errors="replace")
                print(f"{ts()} PY_RESOURCE_COMPLETE:{resource.hash.hex()}:{len(data)}:{text[:80]}", flush=True)
        except Exception as e:
            print(f"{ts()} PY_RESOURCE_CB_ERROR:{type(e).__name__}:{e}", flush=True)
        if phase[0] == "accept_all":
            received_resource_data_all[0] = data
            resource_received_accept_all.set()
        else:
            received_resource_data_app[0] = data
            resource_received_accept_app.set()

    def adv_callback(resource_advertisement):
        print(f"PY_ADV_CALLBACK:hash={resource_advertisement.h.hex()}:size={resource_advertisement.d}", flush=True)
        adv_callback_invoked[0] = True
        return True

    # Wait for Rust announce
    deadline = time.time() + args.timeout
    rust_dest_hash = None
    print("PY_WAITING_FOR_ANNOUNCE", flush=True)

    while time.time() < deadline:
        for h in RNS.Transport.path_table:
            rust_dest_hash = h
            print(f"PY_DISCOVERED:{h.hex()}", flush=True)
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
    print(f"PY_RUST_DEST_HASH:{rust_dest.hexhash}", flush=True)
    print("PY_INITIATING_LINK", flush=True)

    link = RNS.Link(rust_dest, established_callback=link_established_cb,
                     closed_callback=link_closed_cb)

    if not link_established.wait(timeout=15):
        print(f"PY_LINK_TIMEOUT:status={link.status}", flush=True)
        sys.exit(1)

    print(f"{ts()} PY_LINK_ACTIVE", flush=True)
    link.keepalive = 120
    link.stale_time = 240

    # Send Resource from Python to Rust
    resource_text = "test_resource_data_12345 " * 40  # ~1KB
    resource_data = resource_text.encode("utf-8")
    print(f"PY_SENDING_RESOURCE:{len(resource_data)}", flush=True)

    resource_sent = threading.Event()
    def resource_send_complete(resource):
        print(f"{ts()} PY_RESOURCE_SENT:{resource.hash.hex()}:{resource.total_size}", flush=True)
        resource_sent.set()

    resource = RNS.Resource(resource_data, link, callback=resource_send_complete)
    print(f"PY_RESOURCE_HASH:{resource.hash.hex()}", flush=True)

    if not resource_sent.wait(timeout=45):
        print("PY_FAIL:resource_send_timeout", flush=True)
    else:
        print(f"{ts()} PY_RESOURCE_TRANSFER_DONE", flush=True)

    time.sleep(5)

    # Phase 1: ACCEPT_ALL
    phase[0] = "accept_all"
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_resource_started_callback(resource_started_cb)
    link.set_resource_concluded_callback(resource_concluded_cb)
    print(f"{ts()} PY_READY_ACCEPT_ALL", flush=True)

    if resource_received_accept_all.wait(timeout=60):
        print("PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL", flush=True)
    else:
        print("PY_WARN:no_resource_from_rust_accept_all_timeout", flush=True)

    # Phase 2: ACCEPT_APP
    time.sleep(2)
    phase[0] = "accept_app"
    link.set_resource_strategy(RNS.Link.ACCEPT_APP)
    link.set_resource_callback(adv_callback)
    print("PY_READY_ACCEPT_APP", flush=True)

    if resource_received_accept_app.wait(timeout=60):
        if adv_callback_invoked[0]:
            print("PY_RUST_RESOURCE_RECEIVED_ACCEPT_APP", flush=True)
        else:
            print("PY_WARN:resource_received_but_adv_callback_not_invoked", flush=True)
    else:
        print("PY_WARN:no_resource_from_rust_accept_app_timeout", flush=True)

    time.sleep(2)
    link.teardown()
    print("PY_LINK_TEARDOWN_SENT", flush=True)
    time.sleep(2)
    print("PY_DONE", flush=True)


if __name__ == "__main__":
    main()
