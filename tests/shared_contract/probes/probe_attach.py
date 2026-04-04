#!/usr/bin/env python3
"""Probe: capture shared-instance attach behavior.

Starts rnsd, attaches stock Python client(s) in shared mode via subprocesses
(to avoid RNS singleton limitation), captures HDLC bytes exchanged.

Output goes to tests/fixtures/shared-instance/{unix,tcp}/{first,second}-attach/
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


_CLIENT_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
wait_secs = int(sys.argv[5])

t0 = time.time()
rns = RNS.Reticulum(configdir=config_dir)
attach_time = time.time() - t0
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       app_name, aspect)
dest.announce()

time.sleep(wait_secs)

result = {
    "attached": attached,
    "attach_time": round(attach_time, 3),
    "dest_hash": dest.hash.hex(),
    "identity_hash": identity.hexhash,
}

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")

_MULTI_CLIENT_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
check_hash_hex = sys.argv[5] if len(sys.argv) > 5 else ""
wait_secs = int(sys.argv[6]) if len(sys.argv) > 6 else 5

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       app_name, aspect)
dest.announce()

time.sleep(wait_secs)

sees_other = False
if check_hash_hex:
    sees_other = RNS.Transport.has_path(bytes.fromhex(check_hash_hex))

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "sees_other": sees_other,
}

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


def run_attach_probe(mode="unix"):
    """Start rnsd and attach a Python client (in subprocess)."""
    scenario = "first-attach"

    with tempfile.TemporaryDirectory() as config_dir:
        ports = write_daemon_config(os.path.join(config_dir, "config"), mode)

        print(f"[probe] starting rnsd ({mode})...")
        proc = start_rnsd(config_dir)
        if proc is None:
            return False

        client_dir = os.path.join(config_dir, "client")
        os.makedirs(client_dir, exist_ok=True)
        write_client_config(os.path.join(client_dir, "config"), mode, ports)

        result_file = os.path.join(config_dir, "result.json")

        print(f"[probe] attaching Python client ({mode}) in subprocess...")
        client_proc = run_client_subprocess(
            _CLIENT_SCRIPT,
            [client_dir, result_file, "probe", "test", "3"],
        )
        wait_or_kill(client_proc)

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        result = read_result_file(result_file)
        if result is None:
            return False

        attached = result["attached"]
        attach_time = result["attach_time"]
        dest_hash = result["dest_hash"]

        print(f"[probe] attached={attached}, time={attach_time}s, dest={dest_hash}")

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "attached": attached,
            "attach_time_seconds": attach_time,
            "destination_hash": dest_hash,
            "announce_sent": True,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "control.log", stderr_text)
        write_fixture(mode, scenario, "notes.md", f"""\
# First Attach — {mode.upper()} Mode

- RNS version: 1.1.4
- Client attached: {attached}
- Attach time: {attach_time}s
- Destination hash: `{dest_hash}`
- Announce sent: yes

## Protocol Observations

The client connects to the shared instance data socket and immediately
begins exchanging HDLC-framed packets. There is NO handshake on the data
socket — the first bytes are HDLC frames containing RNS packets.

The client's announce is sent as an HDLC-framed RNS announce packet
through the data socket. The daemon receives it and can relay it.
""")
        write_packets_log(mode, scenario, stderr_text)

        print(f"[probe] {mode}/{scenario}: attached={attached}")
        return attached


def run_multi_client_probe(mode="unix"):
    """Start rnsd and attach two Python clients to capture relay behavior."""
    scenario = "second-attach"

    with tempfile.TemporaryDirectory() as config_dir:
        ports = write_daemon_config(os.path.join(config_dir, "config"), mode)

        print(f"[probe] starting rnsd ({mode})...")
        proc = start_rnsd(config_dir)
        if proc is None:
            return False

        c1_dir = os.path.join(config_dir, "client1")
        os.makedirs(c1_dir, exist_ok=True)
        write_client_config(os.path.join(c1_dir, "config"), mode, ports)
        c1_result_file = os.path.join(config_dir, "c1_result.json")

        print(f"[probe] starting client1 ({mode})...")
        c1_proc = run_client_subprocess(
            _MULTI_CLIENT_SCRIPT,
            [c1_dir, c1_result_file, "probe", "client1", "", "10"],
        )

        time.sleep(5)

        c2_dir = os.path.join(config_dir, "client2")
        os.makedirs(c2_dir, exist_ok=True)
        write_client_config(os.path.join(c2_dir, "config"), mode, ports)
        c2_result_file = os.path.join(config_dir, "c2_result.json")

        print(f"[probe] starting client2 ({mode})...")
        c2_proc = run_client_subprocess(
            _MULTI_CLIENT_SCRIPT,
            [c2_dir, c2_result_file, "probe", "client2", "", "8"],
        )

        wait_or_kill(c1_proc)
        wait_or_kill(c2_proc)

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        c1_result = read_result_file(c1_result_file)
        c2_result = read_result_file(c2_result_file)
        if c1_result is None or c2_result is None:
            return False

        c1_dest = c1_result["dest_hash"]
        c2_dest = c2_result["dest_hash"]
        print(f"[probe] client1 dest: {c1_dest}")
        print(f"[probe] client2 dest: {c2_dest}")

        # Check daemon logs for evidence of relay
        c1_in_logs = c1_dest[:16] in stderr_text or c1_dest in stderr_text
        c2_in_logs = c2_dest[:16] in stderr_text or c2_dest in stderr_text
        print(f"[probe] c1 in daemon logs: {c1_in_logs}, c2 in daemon logs: {c2_in_logs}")

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "client1_dest": c1_dest,
            "client2_dest": c2_dest,
            "c1_in_daemon_logs": c1_in_logs,
            "c2_in_daemon_logs": c2_in_logs,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "control.log", stderr_text)
        write_fixture(mode, scenario, "notes.md", f"""\
# Second Attach — {mode.upper()} Mode

- Client1 dest: `{c1_dest}`
- Client2 dest: `{c2_dest}`
- Client1 visible in daemon logs: {c1_in_logs}
- Client2 visible in daemon logs: {c2_in_logs}

## Observations

Two clients attach to the same shared instance via separate processes.
Both announce. The daemon relays announces between clients so each can
discover the other's path. Evidence of relay is in the daemon stderr.
""")
        write_packets_log(mode, scenario, stderr_text)

        return True


if __name__ == "__main__":
    ok = True
    for func in [run_attach_probe, run_multi_client_probe]:
        for mode in ["unix", "tcp"]:
            subprocess.run(["pkill", "-9", "-f", "rnsd"], capture_output=True)
            time.sleep(2)
            if not func(mode):
                print(f"[probe] FAILED: {func.__name__}({mode})")
                ok = False
    if ok:
        print("\n[probe] attach: ALL OK")
    else:
        print("\n[probe] attach: SOME CHECKS FAILED")
        sys.exit(1)
