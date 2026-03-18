"""Shared utilities for rete interop tests."""

import os
import socket
import time


def write_rnsd_config(
    config_dir: str,
    port: int,
    ifac_netname: str = None,
    shared_instance_port: int = None,
) -> str:
    """Write a minimal rnsd config file. Returns the config dir path.

    Args:
        config_dir: Directory for the config file.
        port: TCP server listen port.
        ifac_netname: Optional IFAC network name.
        shared_instance_port: Optional shared instance port override.
    """
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")

    ifac_line = ""
    if ifac_netname:
        ifac_line = f"\n    networkname = {ifac_netname}"

    shared_line = ""
    if shared_instance_port is not None:
        shared_line = f"\n  shared_instance_port = {shared_instance_port}"

    with open(config_path, "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = yes
  share_instance = no{shared_line}

[logging]
  loglevel = 5

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}{ifac_line}
""")
    return config_dir


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    """Wait until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def read_stdout_lines(proc, lines, stop_event):
    """Read stdout lines from a subprocess into a list."""
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        lines.append(line.decode(errors="replace").rstrip("\n"))
