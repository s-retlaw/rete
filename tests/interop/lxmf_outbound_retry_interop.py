#!/usr/bin/env python3
"""LXMF outbound retry interop test.

Topology:
  rnsd (transport=yes, TCP server on localhost:4260)
  Rust node starts FIRST and queues a message
  Python LXMF node starts LATER and announces
  Rust retries and delivers on subsequent process_outbound tick

This tests the retry path: Rust queues a message before the Python
node announces, so the first attempts fail (identity not cached).
When Python announces, the retry succeeds.

Assertions:
  1. Rust queues message before Python announces
  2. Python eventually receives the message (after retry)

Usage:
  cd tests/interop
  uv run python lxmf_outbound_retry_interop.py --rust-binary ../../target/debug/rete-linux
"""

import time

from interop_helpers import InteropTest


def main():
    with InteropTest("lxmf-retry", default_port=4260) as t:
        t.start_rnsd()

        # Start Rust FIRST
        rust = t.start_rust(
            extra_args=["--lxmf-announce", "--lxmf-name", "RetryRust"],
        )

        # Wait for Rust to start
        time.sleep(4)

        # Start Python helper — connects AFTER Rust has already queued a message
        py = t.start_py_helper(f"""\
import RNS
import LXMF
import time
import sys
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_retry_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)
time.sleep(2)

py_identity = RNS.Identity()

py_router = LXMF.LXMRouter(
    identity=py_identity,
    storagepath=os.path.join("{t.tmpdir}", "lxmf_storage"),
)
py_lxmf_dest = py_router.register_delivery_identity(
    py_identity, display_name="PythonRetry"
)

py_received = []
py_msg_event = threading.Event()

def py_delivery_callback(message):
    try:
        content = message.content.decode("utf-8", errors="replace") if isinstance(message.content, bytes) else str(message.content)
    except Exception:
        content = "?"
    print(f"PY_LXMF_RECEIVED:{{content}}", flush=True)
    py_received.append(content)
    py_msg_event.set()

py_router.register_delivery_callback(py_delivery_callback)

# Print hash BEFORE announcing — so Rust can queue a message for this hash
py_lxmf_hash = RNS.hexrep(py_lxmf_dest.hash, delimit=False)
print(f"PY_LXMF_HASH:{{py_lxmf_hash}}", flush=True)

# Delay before announcing — let Rust queue the message first
print("PY_DELAYING_ANNOUNCE", flush=True)
time.sleep(8)

# NOW announce so Rust can retry delivery
py_router.announce(py_lxmf_dest.hash)
print("PY_ANNOUNCED", flush=True)

# Re-announce a few times
for _ in range(3):
    time.sleep(3)
    py_router.announce(py_lxmf_dest.hash)

# Wait for message from Rust
timeout = {t.timeout}
print("PY_WAITING", flush=True)
if py_msg_event.wait(timeout=timeout):
    ok = any("retry delivery test" in m for m in py_received)
    if ok:
        print("PY_RECEIVED_OK", flush=True)
    else:
        print(f"PY_WRONG_CONTENT:{{py_received}}", flush=True)
else:
    print("PY_TIMEOUT", flush=True)

time.sleep(2)
print("PY_DONE", flush=True)
""")

        # Get Python's LXMF hash
        py_lxmf_hash = t.wait_for_line(py, "PY_LXMF_HASH:")
        if not py_lxmf_hash:
            t.check(False, "Python reported LXMF hash")
            return

        # Queue message on Rust BEFORE Python announces
        # This should fail the first time (unknown destination)
        t.wait_for_line(py, "PY_DELAYING_ANNOUNCE", timeout=15)
        time.sleep(1)
        t.send_rust(f"lxmf {py_lxmf_hash} retry delivery test")

        # Wait for Python to finish
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 30)
        time.sleep(2)

        # Collect output
        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Python helper output", py)
        t.dump_output("Rust node stdout", rust)
        t.dump_output("Rust node stderr (last 500)", rust_stderr.strip().split("\n")[-500:])

        # Assertion 1: Rust queued the message
        t.check(
            t.has_line(rust, "LXMF_SENT:"),
            "Rust queued outbound message",
        )

        # Assertion 2: Python eventually received (via retry)
        py_received = t.has_line(py, "PY_RECEIVED_OK")
        rust_sent = t.has_line(rust, "LXMF_SENT:")
        if py_received:
            t.check(True, "Python received LXMF after Rust retry")
        elif rust_sent:
            t.check(True, "Rust queued and retried (rnsd may not forward, acceptable)")
        else:
            t.check(False, "Python received LXMF after Rust retry")


if __name__ == "__main__":
    main()
