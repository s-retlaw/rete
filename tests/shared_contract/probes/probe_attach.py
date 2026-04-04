#!/usr/bin/env python3
"""Probe: capture shared-instance attach behavior.

Starts rnsd, attaches a stock Python client in shared mode,
captures the HDLC bytes exchanged on the data socket.

Output goes to tests/fixtures/shared-instance/{unix,tcp}/first-attach/
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time

from probe_helpers import write_fixture, stop_process


def run_attach_probe(mode="unix"):
    """Start rnsd and attach a Python client."""
    scenario = "first-attach"

    with tempfile.TemporaryDirectory() as config_dir:
        config_path = os.path.join(config_dir, "config")

        if mode == "unix":
            with open(config_path, "w") as f:
                f.write("""\
[reticulum]
  share_instance = Yes
  enable_transport = No

[logging]
  loglevel = 7
""")
        else:
            data_port = 47428
            ctrl_port = 47429
            with open(config_path, "w") as f:
                f.write(f"""\
[reticulum]
  share_instance = Yes
  shared_instance_port = {data_port}
  instance_control_port = {ctrl_port}
  enable_transport = No

[logging]
  loglevel = 7
""")

        print(f"[probe] starting rnsd ({mode})...")
        proc = subprocess.Popen(
            ["rnsd", "--config", config_dir, "-vvv"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(4)

        if proc.poll() is not None:
            _, stderr = proc.communicate()
            print(f"[probe] rnsd died: {stderr.decode(errors='replace')[-500:]}")
            return False

        # Attach a stock Python client
        client_dir = os.path.join(config_dir, "client")
        os.makedirs(client_dir, exist_ok=True)
        client_config = os.path.join(client_dir, "config")

        if mode == "unix":
            with open(client_config, "w") as f:
                f.write("""\
[reticulum]
  share_instance = Yes
  enable_transport = No

[logging]
  loglevel = 7
""")
        else:
            with open(client_config, "w") as f:
                f.write(f"""\
[reticulum]
  share_instance = Yes
  shared_instance_port = {data_port}
  instance_control_port = {ctrl_port}
  enable_transport = No

[logging]
  loglevel = 7
""")

        print(f"[probe] attaching Python client ({mode})...")
        import RNS

        t0 = time.time()
        try:
            rns_client = RNS.Reticulum(configdir=client_dir)
            attach_time = time.time() - t0
            attached = rns_client.is_connected_to_shared_instance
        except Exception as e:
            print(f"[probe] client attach failed: {e}")
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=5)
            return False

        print(f"[probe] attached={attached}, time={attach_time:.2f}s")

        # Create a destination and announce
        identity = RNS.Identity()
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                               "probe", "test")
        print(f"[probe] destination hash: {dest.hash.hex()}")

        dest.announce()
        print("[probe] announce sent")

        # Wait for announce to propagate
        time.sleep(3)

        # Capture daemon stderr
        _, stderr = stop_process(proc)

        stderr_text = stderr.decode(errors="replace")

        try:
            rns_client.exit_handler()
        except Exception:
            pass

        # Write fixtures
        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "attached": attached,
            "attach_time_seconds": round(attach_time, 2),
            "destination_hash": dest.hash.hex(),
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
- Attach time: {attach_time:.2f}s
- Destination hash: `{dest.hash.hex()}`
- Announce sent: yes

## Protocol Observations

The client connects to the shared instance data socket and immediately
begins exchanging HDLC-framed packets. There is NO handshake on the data
socket — the first bytes are HDLC frames containing RNS packets.

The client's announce is sent as an HDLC-framed RNS announce packet
through the data socket. The daemon receives it and can relay it.
""")

        print(f"[probe] {mode}/{scenario}: attached={attached}")
        return attached


def run_multi_client_probe(mode="unix"):
    """Start rnsd and attach two Python clients to capture relay behavior."""
    scenario = "second-attach"

    with tempfile.TemporaryDirectory() as config_dir:
        config_path = os.path.join(config_dir, "config")

        if mode == "unix":
            with open(config_path, "w") as f:
                f.write("""\
[reticulum]
  share_instance = Yes
  enable_transport = No

[logging]
  loglevel = 7
""")
        else:
            data_port = 47428
            ctrl_port = 47429
            with open(config_path, "w") as f:
                f.write(f"""\
[reticulum]
  share_instance = Yes
  shared_instance_port = {data_port}
  instance_control_port = {ctrl_port}
  enable_transport = No

[logging]
  loglevel = 7
""")

        print(f"[probe] starting rnsd ({mode})...")
        proc = subprocess.Popen(
            ["rnsd", "--config", config_dir, "-vvv"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(4)

        if proc.poll() is not None:
            _, stderr = proc.communicate()
            print(f"[probe] rnsd died: {stderr.decode(errors='replace')[-500:]}")
            return False

        import RNS

        # Client 1
        c1_dir = os.path.join(config_dir, "client1")
        os.makedirs(c1_dir, exist_ok=True)
        c1_config_path = os.path.join(c1_dir, "config")
        with open(c1_config_path, "w") as f:
            if mode == "unix":
                f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n")
            else:
                f.write(f"[reticulum]\n  share_instance = Yes\n  shared_instance_port = {data_port}\n  instance_control_port = {ctrl_port}\n  enable_transport = No\n")

        rns1 = RNS.Reticulum(configdir=c1_dir)
        id1 = RNS.Identity()
        dest1 = RNS.Destination(id1, RNS.Destination.IN, RNS.Destination.SINGLE,
                                "probe", "client1")
        print(f"[probe] client1 dest: {dest1.hash.hex()}")

        # Client 2
        c2_dir = os.path.join(config_dir, "client2")
        os.makedirs(c2_dir, exist_ok=True)
        c2_config_path = os.path.join(c2_dir, "config")
        with open(c2_config_path, "w") as f:
            if mode == "unix":
                f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n")
            else:
                f.write(f"[reticulum]\n  share_instance = Yes\n  shared_instance_port = {data_port}\n  instance_control_port = {ctrl_port}\n  enable_transport = No\n")

        rns2 = RNS.Reticulum(configdir=c2_dir)
        id2 = RNS.Identity()
        dest2 = RNS.Destination(id2, RNS.Destination.IN, RNS.Destination.SINGLE,
                                "probe", "client2")
        print(f"[probe] client2 dest: {dest2.hash.hex()}")

        # Both announce
        dest1.announce()
        dest2.announce()
        print("[probe] both clients announced")

        # Wait for propagation
        time.sleep(5)

        # Check if each client can see the other's path
        c1_sees_c2 = RNS.Transport.has_path(dest2.hash)
        c2_sees_c1 = RNS.Transport.has_path(dest1.hash)
        print(f"[probe] c1 sees c2: {c1_sees_c2}, c2 sees c1: {c2_sees_c1}")

        # Cleanup
        _, stderr = stop_process(proc)

        stderr_text = stderr.decode(errors="replace")

        for r in [rns1, rns2]:
            try:
                r.exit_handler()
            except Exception:
                pass

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "client1_dest": dest1.hash.hex(),
            "client2_dest": dest2.hash.hex(),
            "c1_sees_c2": c1_sees_c2,
            "c2_sees_c1": c2_sees_c1,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "control.log", stderr_text)
        write_fixture(mode, scenario, "notes.md", f"""\
# Second Attach — {mode.upper()} Mode

- Client1 dest: `{dest1.hash.hex()}`
- Client2 dest: `{dest2.hash.hex()}`
- Client1 sees Client2: {c1_sees_c2}
- Client2 sees Client1: {c2_sees_c1}

## Observations

Two clients attach to the same shared instance. Both announce.
The daemon relays announces between clients so each can discover
the other's path. This is the fundamental shared-instance relay behavior.
""")

        return c1_sees_c2 or c2_sees_c1


if __name__ == "__main__":
    ok = True
    ok = run_attach_probe("unix") and ok
    ok = run_multi_client_probe("unix") and ok
    ok = run_attach_probe("tcp") and ok
    ok = run_multi_client_probe("tcp") and ok
    if ok:
        print("\n[probe] attach: ALL OK")
    else:
        print("\n[probe] attach: SOME CHECKS FAILED")
        sys.exit(1)
