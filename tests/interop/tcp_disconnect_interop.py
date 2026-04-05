#!/usr/bin/env python3
"""TCP disconnect E2E test: kill rnsd while Rust is connected.

Verifies the Rust node doesn't crash, hang, or SIGSEGV when the transport
relay disappears underneath it.

Topology:
  rnsd (transport=yes, TCP server on localhost:4302)
  Rust node connects as TCP client to rnsd
  Python client connects as TCP client to rnsd (for baseline announce)
  rnsd is killed (SIGKILL) — Rust must survive

Assertions:
  1. Announce exchange succeeded before disconnect
  2. Rust process alive or exited cleanly (no SIGKILL needed)
  3. No panic/SIGSEGV in Rust stderr
  4. Rust detected disconnection (logged an error)

Usage:
  cd tests/interop
  uv run python tcp_disconnect_interop.py --rust-binary ../../target/debug/rete
"""

import os
import signal
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("tcp-disconnect", default_port=4302) as t:
        rnsd_proc = t.start_rnsd()
        rust = t.start_rust()

        # Give Rust time to connect and announce
        time.sleep(3)

        # Start Python client that announces
        py = t.start_py_helper(f"""\
import RNS
import time
import os
import sys

config_dir = os.path.join("{t.tmpdir}", "py_client_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

identity = RNS.Identity()
dest = RNS.Destination(
    identity,
    RNS.Destination.IN,
    RNS.Destination.SINGLE,
    "rete", "example", "v1",
)

dest.announce()
print(f"PY_DEST_HASH:{{dest.hexhash}}", flush=True)
print("PY_ANNOUNCE_SENT", flush=True)

# Wait for Rust announce
deadline = time.time() + {t.timeout}
while time.time() < deadline:
    known = RNS.Transport.path_table
    for h in known:
        if h != dest.hash:
            print(f"PY_DISCOVERED:{{h.hex()}}", flush=True)
            print("PY_DONE", flush=True)
            # Keep alive briefly for the announce to propagate
            time.sleep(3)
            sys.exit(0)
    time.sleep(0.5)

print("PY_FAIL:timeout", flush=True)
print("PY_DONE", flush=True)
""")

        # Wait for Python to discover Rust (baseline exchange)
        t.wait_for_line(py, "PY_DONE", timeout=t.timeout + 10)
        time.sleep(1)

        # Verify baseline: Rust received an announce
        baseline_announce = t.has_line(rust, "ANNOUNCE:")
        t.check(baseline_announce,
                "Announce exchange succeeded before disconnect")

        # Kill rnsd (SIGKILL — abrupt disconnect)
        t._log("killing rnsd with SIGKILL...")
        try:
            rnsd_proc.send_signal(signal.SIGKILL)
            rnsd_proc.wait(timeout=5)
        except Exception:
            pass

        # Wait for Rust to notice the disconnect
        time.sleep(5)

        # Check if Rust process is alive or exited cleanly
        rust_poll = t._rust_proc.poll()
        rust_alive = rust_poll is None
        rust_clean_exit = rust_poll is not None and rust_poll >= 0

        t.check(
            rust_alive or rust_clean_exit,
            "Rust process alive or exited cleanly after rnsd kill",
            detail=f"poll()={rust_poll}",
        )

        # Collect stderr for crash analysis
        rust_stderr = t.collect_rust_stderr(last_chars=3000)

        t.dump_output("Python output", py)
        t.dump_output("Rust stdout", rust)
        t.dump_output("Rust stderr (last 3000)", rust_stderr.strip().split("\n"))

        # Check for panic/SIGSEGV
        has_panic = "panicked" in rust_stderr.lower() or "sigsegv" in rust_stderr.lower()
        t.check(
            not has_panic,
            "No panic/SIGSEGV in Rust stderr",
            detail=f"Found panic indicators in stderr" if has_panic else None,
        )

        # Check that Rust detected the disconnection
        disconnect_detected = (
            "recv error" in rust_stderr.lower()
            or "connection" in rust_stderr.lower()
            or "disconnect" in rust_stderr.lower()
            or "broken pipe" in rust_stderr.lower()
            or "eof" in rust_stderr.lower()
            or "closed" in rust_stderr.lower()
            or "reset" in rust_stderr.lower()
        )
        t.check(
            disconnect_detected,
            "Rust detected disconnection (logged error/warning)",
            detail="No disconnect-related message in stderr" if not disconnect_detected else None,
        )


if __name__ == "__main__":
    main()
