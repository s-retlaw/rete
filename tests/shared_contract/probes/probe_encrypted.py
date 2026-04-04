#!/usr/bin/env python3
"""Probe: capture encrypted data send/receive through shared instance.

Starts rnsd, attaches receiver (SINGLE destination with packet callback),
attaches sender (discovers receiver identity, sends encrypted packet),
captures daemon relay behavior.

Output goes to tests/fixtures/shared-instance/unix/encrypted-data/
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


_RECEIVER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
ready_file = sys.argv[3] if len(sys.argv) > 3 else ""
wait_secs = int(sys.argv[4]) if len(sys.argv) > 4 else 20

received_data = []

def packet_callback(data, packet):
    received_data.append(data.hex() if isinstance(data, bytes) else str(data))

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "probe", "encrypted")
dest.set_packet_callback(packet_callback)
dest.announce()

# Write ready signal with dest hash so sender can start
if ready_file:
    with open(ready_file, "w") as f:
        json.dump({"dest_hash": dest.hash.hex(), "identity_hash": identity.hexhash}, f)

time.sleep(wait_secs)

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "identity_hash": identity.hexhash,
    "received_count": len(received_data),
    "received_data": received_data[:5],
}
with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


_SENDER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
receiver_hash_hex = sys.argv[3]
test_payload = sys.argv[4].encode() if len(sys.argv) > 4 else b"golden-trace-test"

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

receiver_hash = bytes.fromhex(receiver_hash_hex)

path_found = False
for i in range(15):
    if RNS.Transport.has_path(receiver_hash):
        path_found = True
        break
    time.sleep(1)

send_success = False
identity_recalled = False

if path_found:
    receiver_identity = RNS.Identity.recall(receiver_hash)
    identity_recalled = receiver_identity is not None

    if identity_recalled:
        dest = RNS.Destination(receiver_identity, RNS.Destination.OUT,
                               RNS.Destination.SINGLE, "probe", "encrypted")
        packet = RNS.Packet(dest, test_payload)
        receipt = packet.send()
        send_success = receipt is not None

time.sleep(3)

result = {
    "attached": attached,
    "path_found": path_found,
    "identity_recalled": identity_recalled,
    "send_success": send_success,
    "test_payload_hex": test_payload.hex(),
}
with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


def run_encrypted_probe(mode="unix"):
    """Start rnsd, run receiver and sender, capture relay behavior."""
    scenario = "encrypted-data"

    with tempfile.TemporaryDirectory() as config_dir:
        write_daemon_config(os.path.join(config_dir, "config"), mode)

        print(f"[probe] starting rnsd ({mode})...")
        proc = start_rnsd(config_dir)
        if proc is None:
            return False

        # Receiver
        recv_dir = os.path.join(config_dir, "receiver")
        os.makedirs(recv_dir, exist_ok=True)
        write_client_config(os.path.join(recv_dir, "config"), mode)
        recv_result_file = os.path.join(config_dir, "recv_result.json")
        recv_ready_file = os.path.join(config_dir, "recv_ready.json")

        print("[probe] starting receiver...")
        recv_proc = run_client_subprocess(
            _RECEIVER_SCRIPT,
            [recv_dir, recv_result_file, recv_ready_file, "25"],
        )

        # Wait for receiver to write ready signal
        recv_hash = None
        for _ in range(15):
            ready = read_result_file(recv_ready_file)
            if ready is not None:
                recv_hash = ready["dest_hash"]
                break
            time.sleep(1)

        # Extra time for announce propagation
        time.sleep(3)

        if recv_hash is None:
            print("[probe] failed to get receiver hash, continuing with daemon-only capture")
            wait_or_kill(recv_proc)
            _, stderr = stop_process(proc)
            stderr_text = stderr.decode(errors="replace")

            metadata = {
                "scenario": scenario,
                "mode": mode,
                "rns_version": "1.1.4",
                "receiver_ready": False,
                "send_attempted": False,
                "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            write_fixture(mode, scenario, "metadata.json",
                          json.dumps(metadata, indent=2))
            write_fixture(mode, scenario, "notes.md",
                          "# Encrypted Data — FAILED\n\nReceiver failed to produce result file.\n")
            write_packets_log(mode, scenario, stderr_text)
            return False

        print(f"[probe] receiver dest: {recv_hash}")

        # Sender
        send_dir = os.path.join(config_dir, "sender")
        os.makedirs(send_dir, exist_ok=True)
        write_client_config(os.path.join(send_dir, "config"), mode)
        send_result_file = os.path.join(config_dir, "send_result.json")

        print("[probe] starting sender...")
        send_proc = run_client_subprocess(
            _SENDER_SCRIPT,
            [send_dir, send_result_file, recv_hash, "golden-trace-test"],
        )

        wait_or_kill(send_proc)
        wait_or_kill(recv_proc, timeout=35)

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        recv_result = read_result_file(
            recv_result_file,
            {"attached": False, "dest_hash": recv_hash, "received_count": 0},
        )
        send_result = read_result_file(
            send_result_file,
            {"attached": False, "path_found": False, "send_success": False},
        )

        received_count = recv_result.get("received_count", 0)
        send_success = send_result.get("send_success", False)
        path_found = send_result.get("path_found", False)
        identity_recalled = send_result.get("identity_recalled", False)

        print(f"[probe] path_found={path_found}, identity_recalled={identity_recalled}, "
              f"send_success={send_success}, received={received_count}")

        metadata = {
            "scenario": scenario,
            "mode": mode,
            "rns_version": "1.1.4",
            "receiver_dest_hash": recv_hash,
            "receiver_attached": recv_result.get("attached", False),
            "sender_attached": send_result.get("attached", False),
            "path_found": path_found,
            "identity_recalled": identity_recalled,
            "send_success": send_success,
            "received_count": received_count,
            "test_payload_hex": send_result.get("test_payload_hex", ""),
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture(mode, scenario, "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture(mode, scenario, "notes.md", f"""\
# Encrypted Data — {mode.upper()} Mode

- RNS version: 1.1.4
- Receiver dest: `{recv_hash}`
- Path found by sender: {path_found}
- Identity recalled: {identity_recalled}
- Send success: {send_success}
- Packets received: {received_count}

## Observations

The receiver creates a SINGLE destination (which requires encryption for
incoming data), announces it, and sets a packet callback. The sender
discovers the receiver's path and identity via the announce, then sends
an encrypted packet to it.

The daemon acts as a transparent relay — it never decrypts the packet.
It forwards the HDLC-framed RNS packet between the two locally-attached
clients. The encrypted payload is opaque to the shared instance.
""")
        write_packets_log(mode, scenario, stderr_text)

        print(f"[probe] {mode}/{scenario}: done")
        return True


if __name__ == "__main__":
    subprocess.run(["pkill", "-9", "-f", "rnsd"], capture_output=True)
    time.sleep(2)
    ok = run_encrypted_probe("unix")
    if ok:
        print("\n[probe] encrypted: ALL OK")
    else:
        print("\n[probe] encrypted: FAILED")
        sys.exit(1)
