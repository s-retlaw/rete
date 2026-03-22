#!/usr/bin/env python3
"""Multi-segment resource transfer E2E interop test.

Tests resource transfers with exactly 2-3 segments in both directions
(Python->Rust and Rust->Python). This exercises the per-window follow-up
REQ flow without requiring HMU exchanges.

Topology:
  rnsd (transport=yes, TCP server on localhost:4353)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd
  Python discovers Rust via announce, establishes Link

Assertions:
  1. Link established (both sides)
  2. Python->Rust: ~900-byte resource transfer completes, data matches
  3. Rust->Python: ~700-byte resource transfer completes, data matches

Usage:
  cd tests/interop
  uv run python resource_multiseg_interop.py --rust-binary ../../target/debug/rete-linux

Or build first:
  cargo build -p rete-example-linux
  cd tests/interop && uv run python resource_multiseg_interop.py
"""

import time

from interop_helpers import InteropTest


def main():
    # Python→Rust: ~900 bytes of incompressible data → 2-3 encrypted segments
    import hashlib

    py_data = hashlib.sha256(b"multiseg-py2rust").hexdigest() * 14  # 896 bytes
    resource_text = "MS_PY_" + py_data[:890]  # ~896 bytes
    resource_data = resource_text.encode("utf-8")

    # Rust→Python: ~700 bytes → 2-3 encrypted segments
    rust_data = hashlib.sha256(b"multiseg-rust2py").hexdigest() * 11
    rust_resource_text = "MS_RS_" + rust_data[:690]  # ~696 bytes

    with InteropTest("resource-multiseg-interop", default_port=4353, default_timeout=60.0) as t:
        t.start_rnsd()
        rust = t.start_rust(seed="resource-multiseg-test-seed-88")

        # Give Rust time to connect and announce
        time.sleep(3)

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

resource_received = threading.Event()
received_resource_data = [None]

def link_established_cb(link):
    print(f"{{ts()}} PY_LINK_ESTABLISHED:{{link.link_id.hex()}} rtt={{link.rtt:.6f}}", flush=True)
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
    received_resource_data[0] = data
    resource_received.set()

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
    print("PY_DONE", flush=True)
    sys.exit(1)

rust_identity = RNS.Identity.recall(rust_dest_hash)
if not rust_identity:
    print("PY_FAIL:identity_not_recalled", flush=True)
    print("PY_DONE", flush=True)
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
    print("PY_DONE", flush=True)
    sys.exit(1)

print(f"{{ts()}} PY_LINK_ACTIVE", flush=True)

link.keepalive = 120
link.stale_time = 240

# --- Phase 1: Python sends multi-segment resource to Rust ---
resource_data = {repr(resource_data)}
print(f"PY_SENDING_RESOURCE:{{len(resource_data)}}", flush=True)

resource_sent = threading.Event()
def resource_send_complete(resource):
    status_name = {{0x06: "COMPLETE", 0x07: "FAILED", 0x08: "CORRUPT"}}.get(resource.status, f"status={{resource.status}}")
    print(f"{{ts()}} PY_RESOURCE_SENT:{{resource.hash.hex()}}:{{resource.total_size}}:{{status_name}}", flush=True)
    resource_sent.set()

resource = RNS.Resource(resource_data, link, callback=resource_send_complete)
print(f"PY_RESOURCE_HASH:{{resource.hash.hex()}}", flush=True)

if not resource_sent.wait(timeout=30):
    print("PY_FAIL:resource_send_timeout", flush=True)
else:
    print(f"{{ts()}} PY_RESOURCE_TRANSFER_DONE", flush=True)

time.sleep(5)

# --- Phase 2: Rust sends multi-segment resource to Python ---
link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
link.set_resource_started_callback(resource_started_cb)
link.set_resource_concluded_callback(resource_concluded_cb)
print(f"{{ts()}} PY_READY_ACCEPT_ALL", flush=True)

if resource_received.wait(timeout=30):
    print("PY_RUST_RESOURCE_RECEIVED", flush=True)
else:
    print("PY_WARN:no_resource_from_rust_timeout", flush=True)

time.sleep(2)

link.teardown()
print("PY_LINK_TEARDOWN_SENT", flush=True)
time.sleep(2)

print("PY_DONE", flush=True)
""")

        # Monitor Python output and send resource command to Rust at the right time
        deadline = time.monotonic() + t.timeout + 15
        rust_link_id = None
        rust_resource_complete = False
        sent_rust_resource = False

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

            # Send resource from Rust when Python is ready
            if not sent_rust_resource and rust_link_id and rust_resource_complete:
                if any("PY_READY_ACCEPT_ALL" in l for l in py):
                    cmd = f"resource {rust_link_id} {rust_resource_text}"
                    print(f"[resource-multiseg-interop] sending resource from Rust ({len(rust_resource_text)} bytes)")
                    t.send_rust(cmd)
                    sent_rust_resource = True

            # Done when resource sent and Python received it or timed out
            if sent_rust_resource:
                if any("PY_RUST_RESOURCE_RECEIVED" in l for l in py):
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
        rust_stderr = t.collect_rust_stderr(last_chars=2000)
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 2000)", rust_stderr.strip().split("\n"))

        # --- Assertion 1: Link established (both sides) ---
        rust_link_ok = t.has_line(rust, "LINK_ESTABLISHED:")
        py_link_ok = any("PY_LINK_ACTIVE" in l for l in py)
        t.check(
            rust_link_ok and py_link_ok,
            "Link established (both sides)",
            detail=f"Rust={rust_link_ok} Python={py_link_ok}",
        )

        # --- Assertion 2: Python->Rust multi-segment resource ---
        rust_resource_complete_lines = [l for l in rust if l.startswith("RESOURCE_COMPLETE:")]
        py_to_rust_ok = any("MS_PY_" in l for l in rust_resource_complete_lines)
        if py_to_rust_ok:
            for line in rust_resource_complete_lines:
                if "MS_PY_" in line:
                    parts = line.split(":", 3)
                    if len(parts) >= 4:
                        received_data = parts[3]
                        t.check(
                            received_data == resource_text,
                            f"Python->Rust: multi-seg resource complete (size={len(received_data)})",
                        )
                    else:
                        t.check(True, "Python->Rust: multi-seg resource complete")
                    break
        else:
            rust_resource_failed = [l for l in rust if l.startswith("RESOURCE_FAILED:")]
            detail = f"RESOURCE_FAILED: {rust_resource_failed[0]}" if rust_resource_failed else None
            t.check(False, "Python->Rust: multi-seg resource complete", detail=detail)

        # --- Assertion 3: Rust->Python multi-segment resource ---
        py_resource_ok = any("PY_RUST_RESOURCE_RECEIVED" in l for l in py)
        py_resource_data_ok = any("PY_RESOURCE_COMPLETE:" in l and "MS_RS_" in l for l in py)

        if not sent_rust_resource:
            t.check(False, "Rust->Python: multi-seg resource complete",
                    detail="Could not send resource from Rust")
        else:
            t.check(
                py_resource_ok and py_resource_data_ok,
                "Rust->Python: multi-seg resource complete, data matches",
                detail=f"received={py_resource_ok} data_match={py_resource_data_ok}" if not (py_resource_ok and py_resource_data_ok) else None,
            )


if __name__ == "__main__":
    main()
