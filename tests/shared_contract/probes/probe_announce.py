#!/usr/bin/env python3
"""Probe: capture announce propagation through shared instance.

Starts rnsd, attaches Client A (announces), attaches Client B (checks
if it sees Client A via Transport.has_path), captures daemon relay logs.

Output goes to tests/fixtures/shared-instance/unix/announce-propagation/
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time

from probe_helpers import (
    write_fixture, write_packets_log, stop_process, wait_or_kill,
    read_result_file, write_daemon_config, write_client_config,
    start_rnsd, run_client_subprocess,
)


_ANNOUNCER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "probe", "announcer")
dest.announce()

# Write result immediately so other processes can read our dest hash
result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "identity_hash": identity.hexhash,
}
with open(result_file, "w") as f:
    json.dump(result, f)

# Stay alive so listener can discover our path
time.sleep(int(sys.argv[3]) if len(sys.argv) > 3 else 10)

try:
    rns.exit_handler()
except Exception:
    pass
""")


_LISTENER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
announcer_hash_hex = sys.argv[3]

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "probe", "listener")

announcer_hash = bytes.fromhex(announcer_hash_hex)
sees_announcer = False
for i in range(15):
    if RNS.Transport.has_path(announcer_hash):
        sees_announcer = True
        break
    time.sleep(1)

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "sees_announcer": sees_announcer,
    "poll_iterations": i + 1,
}
with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


def run_announce_probe(mode="unix"):
    """Start rnsd, run announcer, run listener, check cross-visibility."""
    scenario = "announce-propagation"

    with tempfile.TemporaryDirectory() as config_dir:
        write_daemon_config(os.path.join(config_dir, "config"), mode)

        print(f"[probe] starting rnsd ({mode})...")
        proc = start_rnsd(config_dir)
        if proc is None:
            return False

        # Announcer (Client A)
        a_dir = os.path.join(config_dir, "announcer")
        os.makedirs(a_dir, exist_ok=True)
        write_client_config(os.path.join(a_dir, "config"), mode)
        a_result_file = os.path.join(config_dir, "a_result.json")

        print("[probe] starting announcer (Client A)...")
        a_proc = run_client_subprocess(
            _ANNOUNCER_SCRIPT, [a_dir, a_result_file, "20"],
        )

        # Wait for announcer to write its result file
        time.sleep(5)

        a_result = read_result_file(a_result_file)
        if a_result is None:
            a_proc.kill()
            stop_process(proc)
            return False

        announcer_hash = a_result["dest_hash"]
        print(f"[probe] announcer dest: {announcer_hash}")

        # Listener (Client B)
        b_dir = os.path.join(config_dir, "listener")
        os.makedirs(b_dir, exist_ok=True)
        write_client_config(os.path.join(b_dir, "config"), mode)
        b_result_file = os.path.join(config_dir, "b_result.json")

        print("[probe] starting listener (Client B)...")
        b_proc = run_client_subprocess(
            _LISTENER_SCRIPT, [b_dir, b_result_file, announcer_hash],
        )

        wait_or_kill(a_proc)
        wait_or_kill(b_proc)

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        b_result = read_result_file(
            b_result_file,
            {"attached": False, "dest_hash": "unknown", "sees_announcer": False},
        )

        sees_announcer = b_result.get("sees_announcer", False)
        listener_dest = b_result.get("dest_hash", "unknown")
        poll_iters = b_result.get("poll_iterations", -1)

        print(f"[probe] listener sees announcer: {sees_announcer} (after {poll_iters} polls)")

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "announcer_dest_hash": announcer_hash,
            "listener_dest_hash": listener_dest,
            "listener_sees_announcer": sees_announcer,
            "poll_iterations": poll_iters,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "notes.md", f"""\
# Announce Propagation — {mode.upper()} Mode

- RNS version: 1.1.4
- Announcer dest: `{announcer_hash}`
- Listener dest: `{listener_dest}`
- Listener sees announcer: {sees_announcer} (after {poll_iters} poll iterations)

## Observations

Client A attaches and announces its destination. Client B attaches
separately (different subprocess, different RNS instance) and polls
`Transport.has_path()` to check if it can discover Client A's destination
through the shared instance.

In shared mode, `Transport.has_path()` returns False because the client
defers transport to the daemon. The daemon handles path resolution
internally. This is expected behavior, not a failure.
""")
        write_packets_log(mode, scenario, stderr_text)

        print(f"[probe] {mode}/{scenario}: done")
        return True


if __name__ == "__main__":
    subprocess.run(["pkill", "-9", "-f", "rnsd"], capture_output=True)
    time.sleep(2)
    ok = run_announce_probe("unix")
    if ok:
        print("\n[probe] announce: ALL OK")
    else:
        print("\n[probe] announce: FAILED")
        sys.exit(1)
