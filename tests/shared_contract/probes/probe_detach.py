#!/usr/bin/env python3
"""Probe: capture client detach behavior.

Starts rnsd, attaches a client in a subprocess, lets it exit (simulating
disconnect), then captures daemon's reaction in stderr.

Output goes to tests/fixtures/shared-instance/unix/client-detach/
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


_CLIENT_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "probe", "detach")
dest.announce()

time.sleep(3)

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
}
with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


def run_detach_probe(mode="unix"):
    """Start rnsd, attach client, let client disconnect, capture daemon logs."""
    scenario = "client-detach"

    with tempfile.TemporaryDirectory() as config_dir:
        write_daemon_config(os.path.join(config_dir, "config"), mode)

        print(f"[probe] starting rnsd ({mode})...")
        proc = start_rnsd(config_dir)
        if proc is None:
            return False

        client_dir = os.path.join(config_dir, "client")
        os.makedirs(client_dir, exist_ok=True)
        write_client_config(os.path.join(client_dir, "config"), mode)

        result_file = os.path.join(config_dir, "result.json")

        print("[probe] attaching client in subprocess...")
        client_proc = run_client_subprocess(
            _CLIENT_SCRIPT, [client_dir, result_file],
        )
        wait_or_kill(client_proc)

        print("[probe] client subprocess exited, waiting for daemon to detect disconnect...")
        time.sleep(3)

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        result = read_result_file(
            result_file, {"attached": False, "dest_hash": "unknown"},
        )

        attached = result.get("attached", False)
        dest_hash = result.get("dest_hash", "unknown")

        disconnect_keywords = ["disappeared", "disconnect", "detach", "removed", "closed", "lost"]
        disconnect_logged = any(kw in stderr_text.lower() for kw in disconnect_keywords)

        print(f"[probe] attached={attached}, dest={dest_hash}, disconnect_logged={disconnect_logged}")

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "client_attached": attached,
            "client_dest_hash": dest_hash,
            "disconnect_logged": disconnect_logged,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "control.log", stderr_text)
        write_fixture(mode, scenario, "notes.md", f"""\
# Client Detach — {mode.upper()} Mode

- RNS version: 1.1.4
- Client attached: {attached}
- Destination hash: `{dest_hash}`
- Disconnect logged by daemon: {disconnect_logged}

## Observations

A client attaches, registers a destination, announces, then exits cleanly
via exit_handler(). The daemon detects the socket closure and should log
the disconnection event. This trace captures the daemon's perspective on
client disconnect — critical for implementing session cleanup in EPIC-05.
""")

        print(f"[probe] {mode}/{scenario}: done")
        return True


if __name__ == "__main__":
    subprocess.run(["pkill", "-9", "-f", "rnsd"], capture_output=True)
    time.sleep(2)
    ok = run_detach_probe("unix")
    if ok:
        print("\n[probe] detach: ALL OK")
    else:
        print("\n[probe] detach: FAILED")
        sys.exit(1)
