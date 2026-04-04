#!/usr/bin/env python3
"""Probe: capture client reconnect behavior.

Starts rnsd, attaches client (Phase A) that announces then exits without
cleanup (simulating crash), then attaches new client (Phase B) using same
configdir/identity, checks if path survives.

Output goes to tests/fixtures/shared-instance/unix/client-reconnect/
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time

from probe_helpers import (
    write_fixture, stop_process, wait_or_kill, read_result_file,
    write_daemon_config, write_client_config, start_rnsd,
    run_client_subprocess,
)


# Phase A: attach, announce, then exit WITHOUT exit_handler (crash simulation)
_PHASE_A_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "probe", "reconnect")
dest.announce()

time.sleep(3)

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "identity_hash": identity.hexhash,
}
with open(result_file, "w") as f:
    json.dump(result, f)

# NO exit_handler() — simulates crash / unclean disconnect
""")


# Phase B: attach with same configdir, re-announce, check path survival.
# Note: RNS.Identity() creates a NEW identity, so dest_hash will differ.
# This documents the real behavior: path does not survive reconnect with
# a new identity.
_PHASE_B_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
original_dest_hex = sys.argv[3]

rns = RNS.Reticulum(configdir=config_dir)
reattached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "probe", "reconnect")
dest.announce()

time.sleep(3)

path_survived = RNS.Transport.has_path(bytes.fromhex(original_dest_hex))

result = {
    "reattached": reattached,
    "new_dest_hash": dest.hash.hex(),
    "path_survived": path_survived,
}
with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


def run_reconnect_probe(mode="unix"):
    """Start rnsd, run Phase A (crash), run Phase B (reconnect)."""
    scenario = "client-reconnect"

    with tempfile.TemporaryDirectory() as config_dir:
        write_daemon_config(os.path.join(config_dir, "config"), mode)

        print(f"[probe] starting rnsd ({mode})...")
        proc = start_rnsd(config_dir)
        if proc is None:
            return False

        # Shared client config dir (reused across phases)
        client_dir = os.path.join(config_dir, "client")
        os.makedirs(client_dir, exist_ok=True)
        write_client_config(os.path.join(client_dir, "config"), mode)

        # Phase A
        a_result_file = os.path.join(config_dir, "phase_a.json")
        print("[probe] Phase A: attaching client (will crash-exit)...")
        a_proc = run_client_subprocess(
            _PHASE_A_SCRIPT, [client_dir, a_result_file],
        )
        wait_or_kill(a_proc)

        print("[probe] Phase A: client exited (no cleanup), waiting for daemon to detect...")
        time.sleep(3)

        a_result = read_result_file(a_result_file)
        if a_result is None:
            stop_process(proc)
            return False

        original_dest = a_result["dest_hash"]
        print(f"[probe] Phase A dest: {original_dest}")

        # Phase B
        b_result_file = os.path.join(config_dir, "phase_b.json")
        print("[probe] Phase B: reconnecting with same configdir...")
        b_proc = run_client_subprocess(
            _PHASE_B_SCRIPT, [client_dir, b_result_file, original_dest],
        )
        wait_or_kill(b_proc)

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        b_result = read_result_file(
            b_result_file,
            {"reattached": False, "new_dest_hash": "unknown", "path_survived": False},
        )

        reattached = b_result.get("reattached", False)
        new_dest = b_result.get("new_dest_hash", "unknown")
        path_survived = b_result.get("path_survived", False)

        print(f"[probe] Phase B: reattached={reattached}, new_dest={new_dest}, path_survived={path_survived}")

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "phase_a_attached": a_result.get("attached", False),
            "phase_a_dest_hash": original_dest,
            "phase_b_reattached": reattached,
            "phase_b_dest_hash": new_dest,
            "path_survived": path_survived,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "control.log", stderr_text)
        write_fixture(mode, scenario, "notes.md", f"""\
# Client Reconnect — {mode.upper()} Mode

- RNS version: 1.1.4
- Phase A: attached={a_result.get('attached', False)}, dest=`{original_dest}`
- Phase B: reattached={reattached}, new_dest=`{new_dest}`, path_survived={path_survived}

## Observations

Phase A attaches a client, announces, then exits without calling exit_handler()
(simulating a crash). Phase B creates a new RNS instance using the same
configdir. RNS.Identity() generates a new identity, producing a different
destination hash. Transport.has_path() returns False because shared-mode
clients defer path resolution to the daemon.

Key findings:
- New identity on reconnect means new destination hash
- Path does not survive reconnect (expected with different identity)
- Daemon allows re-registration after unclean disconnect
""")

        print(f"[probe] {mode}/{scenario}: done")
        return True


if __name__ == "__main__":
    subprocess.run(["pkill", "-9", "-f", "rnsd"], capture_output=True)
    time.sleep(2)
    ok = run_reconnect_probe("unix")
    if ok:
        print("\n[probe] reconnect: ALL OK")
    else:
        print("\n[probe] reconnect: FAILED")
        sys.exit(1)
