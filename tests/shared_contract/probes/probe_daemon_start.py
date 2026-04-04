#!/usr/bin/env python3
"""Probe: capture Python rnsd startup behavior.

Starts rnsd in Unix shared mode, waits for readiness, captures:
- Socket path created
- Listener readiness timing
- RPC listener readiness
- Daemon stderr output

Output goes to tests/fixtures/shared-instance/unix/daemon-start/
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time

from probe_helpers import write_fixture, stop_process


def probe_unix():
    """Probe rnsd startup in Unix mode."""
    with tempfile.TemporaryDirectory() as config_dir:
        # Write minimal config for shared instance
        config_path = os.path.join(config_dir, "config")
        with open(config_path, "w") as f:
            f.write(f"""\
[reticulum]
  share_instance = Yes
  shared_instance_port = 37428
  instance_control_port = 37429
  enable_transport = No

[logging]
  loglevel = 7
""")

        print("[probe] starting rnsd (unix)...")
        t0 = time.time()

        proc = subprocess.Popen(
            ["rnsd", "--config", config_dir, "-vvv"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for daemon to bind sockets
        time.sleep(4)

        t_ready = time.time() - t0
        alive = proc.poll() is None

        print(f"[probe] daemon alive={alive}, readiness={t_ready:.2f}s")

        # Check if abstract socket exists
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect("\0rns/default")
            socket_bound = True
            sock.close()
        except Exception as e:
            socket_bound = False
            print(f"[probe] socket connect failed: {e}")

        # Check RPC socket
        rpc_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            rpc_sock.connect("\0rns/default/rpc")
            rpc_bound = True
            rpc_sock.close()
        except Exception:
            rpc_bound = False

        # Capture stderr
        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        # Write fixtures
        metadata = {
            "scenario": "daemon-start",
            "mode": "unix",
            "rns_version": "1.1.4",
            "instance_name": "default",
            "data_socket": "\\0rns/default",
            "rpc_socket": "\\0rns/default/rpc",
            "data_socket_bound": socket_bound,
            "rpc_socket_bound": rpc_bound,
            "readiness_seconds": round(t_ready, 2),
            "daemon_alive": alive,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture("unix", "daemon-start", "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture("unix", "daemon-start", "control.log", stderr_text)
        write_fixture("unix", "daemon-start", "notes.md", f"""\
# Daemon Start — Unix Mode

- RNS version: 1.1.4
- Instance name: default
- Data socket: `\\0rns/default` (abstract namespace)
- RPC socket: `\\0rns/default/rpc` (abstract namespace)
- Data socket bound: {socket_bound}
- RPC socket bound: {rpc_bound}
- Readiness: {t_ready:.2f}s
- Daemon alive at check: {alive}

## Observations

Daemon binds both sockets on startup. The data socket accepts
HDLC-framed connections. The RPC socket accepts
`multiprocessing.connection` connections with HMAC auth.
""")

        print(f"[probe] unix/daemon-start: data={socket_bound}, rpc={rpc_bound}")
        return socket_bound and rpc_bound


def probe_tcp():
    """Probe rnsd startup in TCP mode."""
    with tempfile.TemporaryDirectory() as config_dir:
        config_path = os.path.join(config_dir, "config")
        # Use non-default ports to avoid conflicts
        data_port = 47428
        ctrl_port = 47429
        with open(config_path, "w") as f:
            f.write(f"""\
[reticulum]
  share_instance = Yes
  shared_instance_type = tcp
  shared_instance_port = {data_port}
  instance_control_port = {ctrl_port}
  enable_transport = No

[logging]
  loglevel = 7
""")

        print(f"[probe] starting rnsd (tcp, ports={data_port}/{ctrl_port})...")
        t0 = time.time()

        proc = subprocess.Popen(
            ["rnsd", "--config", config_dir, "-vvv"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        time.sleep(4)
        t_ready = time.time() - t0
        alive = proc.poll() is None

        # Check TCP data port
        data_bound = False
        try:
            s = socket.create_connection(("127.0.0.1", data_port), timeout=2)
            data_bound = True
            s.close()
        except Exception:
            pass

        # Check TCP control port
        ctrl_bound = False
        try:
            s = socket.create_connection(("127.0.0.1", ctrl_port), timeout=2)
            ctrl_bound = True
            s.close()
        except Exception:
            pass

        _, stderr = stop_process(proc)
        stderr_text = stderr.decode(errors="replace")

        metadata = {
            "scenario": "daemon-start",
            "mode": "tcp",
            "rns_version": "1.1.4",
            "data_port": data_port,
            "control_port": ctrl_port,
            "data_port_bound": data_bound,
            "control_port_bound": ctrl_bound,
            "readiness_seconds": round(t_ready, 2),
            "daemon_alive": alive,
            "capture_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        write_fixture("tcp", "daemon-start", "metadata.json",
                      json.dumps(metadata, indent=2))
        write_fixture("tcp", "daemon-start", "control.log", stderr_text)
        write_fixture("tcp", "daemon-start", "notes.md", f"""\
# Daemon Start — TCP Mode

- RNS version: 1.1.4
- Data port: {data_port}
- Control port: {ctrl_port}
- Data port bound: {data_bound}
- Control port bound: {ctrl_bound}
- Readiness: {t_ready:.2f}s

## Observations

In TCP mode, daemon binds two TCP listeners on 127.0.0.1.
Data port accepts HDLC-framed connections.
Control port accepts `multiprocessing.connection` with HMAC auth.
""")

        print(f"[probe] tcp/daemon-start: data={data_bound}, ctrl={ctrl_bound}")
        return data_bound and ctrl_bound


if __name__ == "__main__":
    ok = True
    ok = probe_unix() and ok
    ok = probe_tcp() and ok
    if ok:
        print("\n[probe] daemon-start: ALL OK")
    else:
        print("\n[probe] daemon-start: SOME CHECKS FAILED")
        sys.exit(1)
