#!/usr/bin/env python3
"""IFAC + Link interop test: Link establishment through IFAC-protected interface.

Topology:
  rnsd (transport=yes, TCP server on localhost:4284, ifac="link-test-net")
  Rust node connects as TCP client (with IFAC)
  Python client connects as TCP client (with IFAC), establishes link to Rust

Assertions:
  1. Link established through IFAC interface
  2. Link data received by Rust
  3. Link teardown works
  4. Rust reports IFAC enabled

Usage:
  cd tests/interop
  uv run python ifac_link_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest

IFAC_NETNAME = "link-test-net"


def main():
    with InteropTest("ifac-link", default_port=4284) as t:
        t.start_rnsd(ifac_netname=IFAC_NETNAME)
        rust = t.start_rust(
            seed="ifac-link-test-seed-88",
            extra_args=["--ifac-netname", IFAC_NETNAME],
        )

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)

ifac_config = "\\n    networkname = {IFAC_NETNAME}"
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"
[reticulum]
  enable_transport = no
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {t.port}
    networkname = {IFAC_NETNAME}
\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

link_established = threading.Event()
link_closed = threading.Event()
active_link = [None]

def link_established_cb(link):
    print(f"PY_LINK_ESTABLISHED:{{link.link_id.hex()}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"PY_LINK_CLOSED:{{link.link_id.hex()}}", flush=True)
    link_closed.set()

py_identity = RNS.Identity()
py_dest = RNS.Destination(
    py_identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
py_dest.announce()
print(f"PY_DEST_HASH:{{py_dest.hexhash}}", flush=True)

# Wait for Rust announce
timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None
while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != py_dest.hash:
            rust_dest_hash = h
            break
    if rust_dest_hash:
        break
    time.sleep(0.5)

if not rust_dest_hash:
    print("PY_FAIL:timeout_waiting_for_rust_announce", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

print(f"PY_DISCOVERED:{{rust_dest_hash.hex()}}", flush=True)

rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

rust_dest = RNS.Destination(
    rust_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

# Establish link through IFAC-protected interface
link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"PY_FAIL:link_not_established status={{link.status}}", flush=True)
    print("PY_DONE", flush=True)
    sys.exit(1)

print("PY_LINK_ACTIVE", flush=True)

# Send data over link
pkt = RNS.Packet(link, b"hello via ifac link")
pkt.send()
print("PY_LINK_DATA_SENT", flush=True)

time.sleep(3)

# Teardown
link.teardown()
time.sleep(2)
print("PY_DONE", flush=True)
""")

        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 10)
        time.sleep(2)

        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)

        # --- Assertion 1: Link established through IFAC ---
        py_link_ok = t.has_line(py, "PY_LINK_ACTIVE") or t.has_line(py, "PY_LINK_ESTABLISHED:")
        rust_link_ok = t.has_line(rust, "LINK_ESTABLISHED:")
        t.check(
            py_link_ok and rust_link_ok,
            "Link established through IFAC interface",
            detail=f"Python={py_link_ok} Rust={rust_link_ok}",
        )

        # --- Assertion 2: Link data received by Rust ---
        t.check(
            t.has_line(rust, "LINK_DATA:", contains="hello via ifac link"),
            "Link data received by Rust through IFAC",
        )

        # --- Assertion 3: Link teardown ---
        t.check(
            t.has_line(rust, "LINK_CLOSED:"),
            "Link teardown works through IFAC",
        )

        # --- Assertion 4: Rust reports IFAC enabled ---
        t.check(
            "IFAC enabled" in rust_stderr,
            "Rust reports IFAC enabled",
        )


if __name__ == "__main__":
    main()
