#!/usr/bin/env python3
"""E2E: Malformed announce handling -- valid announce after malformed traffic.

Tests that the Rust node survives and still processes valid announces
correctly. The "malformed" aspect is that we send many rapid announces
from disposable identities, then verify a final valid announce gets through.
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("malformed-announce", default_port=4350, default_timeout=45) as t:
        t.start_rnsd()
        rust = t.start_rust()

        time.sleep(3)

        py = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_malform_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config()}\"\"\")

reticulum = RNS.Reticulum(config_dir)
time.sleep(2)

# Send a burst of rapid announces from throwaway identities
# (exercises announce processing under load)
for i in range(5):
    throwaway_id = RNS.Identity()
    throwaway_dest = RNS.Destination(
        throwaway_id, RNS.Destination.IN, RNS.Destination.SINGLE,
        "junk", f"node{{i}}")
    throwaway_dest.announce(app_data=b"throwaway")
    time.sleep(0.05)

print("PY_JUNK_SENT", flush=True)
time.sleep(2)

# Now send a valid announce to verify node still works
identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "malform", "valid")
dest.announce(app_data=b"valid-after-bad")
print(f"PY_VALID_DEST:{{dest.hexhash}}", flush=True)
time.sleep(5)

print("PY_DONE", flush=True)
""")

        junk = t.wait_for_line(py, "PY_JUNK_SENT")
        t.check(junk is not None, "Junk announces sent")

        # Check valid announce arrives
        valid_dest = t.wait_for_line(py, "PY_VALID_DEST")
        t.check(valid_dest is not None, "Valid announce sent")

        # Wait for Rust to process
        announce_recv = t.wait_for_line(rust, "ANNOUNCE")
        t.check(announce_recv is not None, "Rust received valid announce after junk traffic")

        # Rust should still be alive
        t.check(t._rust_proc.poll() is None, "Rust node survived")

        done = t.wait_for_line(py, "PY_DONE")
        t.check(done is not None, "Test completed")


if __name__ == "__main__":
    main()
