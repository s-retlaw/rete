#!/usr/bin/env python3
"""Resource E2E interop test: Python transfers Resource to Rust node via Link.

Topology:
  rnsd (transport=yes, TCP server on localhost:4254)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, establishes Link, sends Resource

Assertions:
  1. Link established (both sides)
  2. Python sends Resource (~1KB), Rust receives RESOURCE_OFFERED
  3. Rust receives RESOURCE_COMPLETE with matching data
  4. Rust sends Resource to Python (ACCEPT_ALL strategy), Python receives it
  5. Rust sends Resource to Python (ACCEPT_APP strategy), Python's callback invoked and resource received

Usage:
  cd tests/interop
  uv run python resource_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python resource_interop.py
"""

import time

from interop_helpers import InteropTest


def main():
    # Known test data for resource transfer
    resource_text = "test_resource_data_12345 " * 40  # ~1KB
    resource_data = resource_text.encode("utf-8")

    with InteropTest("resource-interop", default_port=4254, default_timeout=120.0) as t:
        t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python client that discovers Rust, links, and transfers resources
        py = t.start_py_helper(f"""\
import RNS
import time
import sys
import os
import threading

def ts():
    return f"[{{time.time():.3f}}]"

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

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
    print(f"{{ts()}} PY_LINK_ESTABLISHED:{{link.link_id.hex()}} rtt={{link.rtt:.6f}} keepalive={{link.keepalive:.1f}} stale={{link.stale_time:.1f}}", flush=True)
    active_link[0] = link
    link_established.set()

def link_closed_cb(link):
    print(f"{{ts()}} PY_LINK_CLOSED:{{link.link_id.hex()}} status={{link.status}}", flush=True)
    link_closed.set()

def resource_started_cb(resource):
    print(f"{{ts()}} PY_RESOURCE_STARTED:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)

def resource_concluded_cb(resource):
    data = b""
    try:
        status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(resource.status, f"status={{resource.status}}")
        print(f"{{ts()}} PY_RESOURCE_CONCLUDED:{{resource.hash.hex()}}:{{status_name}}", flush=True)
        if resource.status == 0x06:
            if hasattr(resource, 'storagepath') and os.path.isfile(resource.storagepath):
                with open(resource.storagepath, "rb") as f:
                    data = f.read()
            elif hasattr(resource, 'data') and resource.data is not None:
                if hasattr(resource.data, 'read'):
                    data = resource.data.read()
                    resource.data.close()
                elif isinstance(resource.data, (bytes, bytearray)):
                    data = resource.data
                else:
                    data = b""
            else:
                data = b""
            text = data.decode("utf-8", errors="replace")
            print(f"{{ts()}} PY_RESOURCE_COMPLETE:{{resource.hash.hex()}}:{{len(data)}}:{{text[:80]}}", flush=True)
    except Exception as e:
        print(f"{{ts()}} PY_RESOURCE_CB_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    if phase[0] == "accept_all":
        received_resource_data_all[0] = data
        resource_received_accept_all.set()
    else:
        received_resource_data_app[0] = data
        resource_received_accept_app.set()

def adv_callback(resource_advertisement):
    print(f"PY_ADV_CALLBACK:hash={{resource_advertisement.h.hex()}}:size={{resource_advertisement.d}}", flush=True)
    adv_callback_invoked[0] = True
    return True

# Wait for Rust announce
timeout = {t.timeout}
deadline = time.time() + timeout
rust_dest_hash = None

print("PY_WAITING_FOR_ANNOUNCE", flush=True)

while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        rust_dest_hash = h
        print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
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
    rust_identity,
    RNS.Destination.OUT,
    RNS.Destination.SINGLE,
    "rete",
    "example",
    "v1",
)

print(f"PY_RUST_DEST_HASH:{{rust_dest.hexhash}}", flush=True)

print("PY_INITIATING_LINK", flush=True)
link = RNS.Link(rust_dest, established_callback=link_established_cb, closed_callback=link_closed_cb)

if not link_established.wait(timeout=15):
    print(f"PY_LINK_TIMEOUT:status={{link.status}}", flush=True)
    sys.exit(1)

print(f"{{ts()}} PY_LINK_ACTIVE", flush=True)

link.keepalive = 120
link.stale_time = 240

# Send Resource from Python to Rust
resource_data = {repr(resource_data)}
print(f"PY_SENDING_RESOURCE:{{len(resource_data)}}", flush=True)

resource_sent = threading.Event()
def resource_send_complete(resource):
    print(f"{{ts()}} PY_RESOURCE_SENT:{{resource.hash.hex()}}:{{resource.total_size}}", flush=True)
    resource_sent.set()

resource = RNS.Resource(resource_data, link, callback=resource_send_complete)
print(f"PY_RESOURCE_HASH:{{resource.hash.hex()}}", flush=True)

if not resource_sent.wait(timeout=45):
    print("PY_FAIL:resource_send_timeout", flush=True)
else:
    print(f"{{ts()}} PY_RESOURCE_TRANSFER_DONE", flush=True)

time.sleep(5)

# Phase 1: ACCEPT_ALL
phase[0] = "accept_all"
link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
link.set_resource_started_callback(resource_started_cb)
link.set_resource_concluded_callback(resource_concluded_cb)
print(f"{{ts()}} PY_READY_ACCEPT_ALL", flush=True)

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
""")

        # Monitor Python output and send resource commands to Rust at the right time
        deadline = time.monotonic() + t.timeout + 15
        rust_link_id = None
        rust_resource_complete = False
        sent_accept_all = False
        sent_accept_app = False

        while time.monotonic() < deadline:
            # Get Rust link_id
            if rust_link_id is None:
                for line in rust:
                    if line.startswith("LINK_ESTABLISHED:"):
                        rust_link_id = line.split(":")[1].strip()
                        break

            # Check if Rust received the resource from Python
            if not rust_resource_complete:
                for line in rust:
                    if line.startswith("RESOURCE_COMPLETE:"):
                        rust_resource_complete = True
                        break

            # Send first resource (ACCEPT_ALL) when Python is ready
            if not sent_accept_all and rust_link_id and rust_resource_complete:
                if any("PY_READY_ACCEPT_ALL" in l for l in py):
                    cmd = f"resource {rust_link_id} hello_accept_all"
                    print(f"[resource-interop] sending ACCEPT_ALL resource: {cmd}")
                    t.send_rust(cmd)
                    sent_accept_all = True

            # Send second resource (ACCEPT_APP) when Python is ready
            if not sent_accept_app and sent_accept_all:
                if (any("PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL" in l for l in py)
                        and any("PY_READY_ACCEPT_APP" in l for l in py)):
                    cmd = f"resource {rust_link_id} hello_accept_app"
                    print(f"[resource-interop] sending ACCEPT_APP resource: {cmd}")
                    t.send_rust(cmd)
                    sent_accept_app = True

            # Done when both resources sent
            if sent_accept_app:
                time.sleep(3)
                break

            # Check if Python helper has exited
            if any("PY_DONE" in l for l in py):
                break

            time.sleep(0.5)

        # Wait for Python helper to complete
        t.wait_for_line(py, "PY_DONE", timeout=max(5, deadline - time.monotonic()))
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr(last_chars=1000)
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 1000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Link established (both sides) ---
        rust_link_ok = t.has_line(rust, "LINK_ESTABLISHED:")
        py_link_ok = any("PY_LINK_ACTIVE" in l for l in py)
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        # --- Assertion 2: Rust received RESOURCE_OFFERED ---
        rust_resource_offered = [l for l in rust if l.startswith("RESOURCE_OFFERED:")]
        if rust_resource_offered:
            parts = rust_resource_offered[0].split(":")
            if len(parts) >= 4:
                reported_size = int(parts[3])
                t.check(reported_size > 0,
                        f"Rust received RESOURCE_OFFERED (size={reported_size})")
            else:
                t.check(True, "Rust received RESOURCE_OFFERED")
        else:
            t.check(False, "Rust received RESOURCE_OFFERED",
                    detail="link was not established" if not (rust_link_ok and py_link_ok) else None)

        # --- Assertion 3: Rust received RESOURCE_COMPLETE with matching data ---
        rust_resource_complete_lines = [l for l in rust if l.startswith("RESOURCE_COMPLETE:")]
        if rust_resource_complete_lines:
            complete_line = rust_resource_complete_lines[0]
            parts = complete_line.split(":", 3)
            if len(parts) >= 4:
                received_text = parts[3]
                t.check(
                    "test_resource_data_12345" in received_text,
                    "Rust received RESOURCE_COMPLETE with matching data",
                    detail=f"Received (first 100 chars): {received_text[:100]}" if "test_resource_data_12345" not in received_text else None,
                )
            else:
                t.check(False, "Rust received RESOURCE_COMPLETE with matching data",
                        detail=f"Unexpected format: {complete_line}")
        else:
            rust_resource_failed = [l for l in rust if l.startswith("RESOURCE_FAILED:")]
            detail = f"RESOURCE_FAILED: {rust_resource_failed[0]}" if rust_resource_failed else None
            t.check(False, "Rust received RESOURCE_COMPLETE with matching data", detail=detail)

        # --- Assertion 4: Rust->Python with ACCEPT_ALL ---
        py_resource_all_ok = any("PY_RUST_RESOURCE_RECEIVED_ACCEPT_ALL" in l for l in py)
        py_resource_all_complete = any("PY_RESOURCE_COMPLETE:" in l and "hello_accept_all" in l for l in py)

        if not sent_accept_all:
            t.check(False, "Rust->Python with ACCEPT_ALL",
                    detail="Could not send ACCEPT_ALL resource from Rust")
        else:
            t.check(
                py_resource_all_ok and py_resource_all_complete,
                "Rust->Python with ACCEPT_ALL -- Python received resource",
            )

        # --- Assertion 5: Rust->Python with ACCEPT_APP ---
        py_resource_app_ok = any("PY_RUST_RESOURCE_RECEIVED_ACCEPT_APP" in l for l in py)
        py_adv_invoked = any("PY_ADV_CALLBACK:" in l for l in py)
        py_resource_app_complete = any("PY_RESOURCE_COMPLETE:" in l and "hello_accept_app" in l for l in py)

        if not sent_accept_app:
            t.check(False, "Rust->Python with ACCEPT_APP",
                    detail="Could not send ACCEPT_APP resource from Rust")
        else:
            t.check(
                py_resource_app_ok and py_adv_invoked and py_resource_app_complete,
                "Rust->Python with ACCEPT_APP -- callback invoked and resource received",
            )


if __name__ == "__main__":
    main()
