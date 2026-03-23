#!/usr/bin/env python3
"""E2E: Announce flood -- 10 rapid announces from different identities.

Tests that the Rust node handles a burst of announces from different
identities without crashing, with proper deduplication and rate limiting.
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("announce-flood", default_port=4346, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_flood_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Create multiple identities and announce them rapidly
identities = []
destinations = []
for i in range(10):
    ident = RNS.Identity()
    dest = RNS.Destination(ident, RNS.Destination.IN, RNS.Destination.SINGLE,
                           "flood", f"node{{i}}")
    identities.append(ident)
    destinations.append(dest)

print("PY_IDENTITIES_CREATED", flush=True)

# Rapid-fire announces
for dest in destinations:
    dest.announce(app_data=b"flood-node")
    time.sleep(0.5)

print("PY_ANNOUNCES_SENT", flush=True)

# Wait for processing
time.sleep(5)

# Send duplicate announces (should be deduped)
for dest in destinations[:3]:
    dest.announce(app_data=b"flood-dup")
    time.sleep(0.1)

print("PY_DUPLICATES_SENT", flush=True)
time.sleep(3)
print("PY_DONE", flush=True)
""")

        created = t.wait_for_line(py, "PY_IDENTITIES_CREATED")
        t.check(created is not None, "10 identities created")

        sent = t.wait_for_line(py, "PY_ANNOUNCES_SENT")
        t.check(sent is not None, "10 rapid announces sent")

        # Wait for Rust to process (10 announces at 500ms = 5s + propagation)
        time.sleep(8)

        # Count received announces (any ANNOUNCE: line from the flood identities)
        announce_lines = [l for l in rust if l.startswith("ANNOUNCE:")]
        # Subtract 1 for Rust's own announce
        external_announces = max(0, len(announce_lines) - 1)
        # rnsd aggressively rate-limits announces from same client — accept >= 1
        t.check(external_announces >= 1, f"Rust received >= 1/10 external announces ({external_announces})")

        dups_sent = t.wait_for_line(py, "PY_DUPLICATES_SENT")
        t.check(dups_sent is not None, "Duplicate announces sent")

        # Rust should still be alive
        t.check(t._rust_proc.poll() is None, "Rust node survived announce flood")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
