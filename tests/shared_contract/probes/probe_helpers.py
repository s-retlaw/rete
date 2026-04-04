"""Shared helpers for golden trace probe scripts."""

import json
import os
import re
import signal
import subprocess
import sys
import time

FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "fixtures", "shared-instance"
)


def write_fixture(mode, scenario, filename, content):
    """Write a fixture file to the shared-instance fixture tree."""
    path = os.path.join(FIXTURE_DIR, mode, scenario, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(content, bytes):
        with open(path, "wb") as f:
            f.write(content)
    else:
        with open(path, "w") as f:
            f.write(content)
    print(f"  wrote {path}")


def stop_process(proc, timeout=5):
    """Send SIGTERM and wait, falling back to SIGKILL."""
    proc.send_signal(signal.SIGTERM)
    try:
        return proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate()


def wait_or_kill(proc, timeout=30):
    """Wait for a subprocess to finish, killing it on timeout."""
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def read_result_file(path, default=None):
    """Read a JSON result file written by a subprocess probe."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[probe] failed to read {path}: {e}")
        return default


def write_daemon_config(config_path, mode):
    """Write rnsd daemon config. Returns port dict for TCP mode."""
    if mode == "unix":
        with open(config_path, "w") as f:
            f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n\n[logging]\n  loglevel = 7\n")
        return {}
    else:
        data_port = 47428
        ctrl_port = 47429
        with open(config_path, "w") as f:
            f.write(f"[reticulum]\n  share_instance = Yes\n  shared_instance_port = {data_port}\n  instance_control_port = {ctrl_port}\n  enable_transport = No\n\n[logging]\n  loglevel = 7\n")
        return {"data_port": data_port, "ctrl_port": ctrl_port}


def write_client_config(config_path, mode, ports=None):
    """Write shared-mode client config."""
    if mode == "unix":
        with open(config_path, "w") as f:
            f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n\n[logging]\n  loglevel = 7\n")
    else:
        with open(config_path, "w") as f:
            f.write(f"[reticulum]\n  share_instance = Yes\n  shared_instance_port = {ports['data_port']}\n  instance_control_port = {ports['ctrl_port']}\n  enable_transport = No\n\n[logging]\n  loglevel = 7\n")


def start_rnsd(config_dir, wait=4):
    """Start rnsd and wait for readiness. Returns process or None."""
    proc = subprocess.Popen(
        ["rnsd", "--config", config_dir, "-vvv"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(wait)
    if proc.poll() is not None:
        _, stderr = proc.communicate()
        print(f"[probe] rnsd died: {stderr.decode(errors='replace')[-500:]}")
        return None
    return proc


def run_client_subprocess(script_text, args):
    """Run a client script in a subprocess, return the process."""
    return subprocess.Popen(
        [sys.executable, "-c", script_text] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


# Patterns that indicate packet-level activity in daemon stderr at loglevel 7
_PACKET_PATTERNS = re.compile(
    r"(packet|announce|incoming|outgoing|hdlc|destination|transport\.|"
    r"received|sending|propagat|relay|\b[0-9a-f]{32}\b)",
    re.IGNORECASE,
)


def extract_packets_log(stderr_text):
    """Extract packet-related lines from daemon stderr (loglevel 7).

    Returns a string suitable for writing as packets.log.
    """
    lines = stderr_text.splitlines()
    included = set()
    matched = []
    for i, line in enumerate(lines):
        if _PACKET_PATTERNS.search(line):
            for j in (i - 1, i, i + 1):
                if 0 <= j < len(lines) and j not in included:
                    included.add(j)
                    matched.append(lines[j])
    if not matched:
        return "# No packet-level lines found in daemon stderr at loglevel 7.\n"
    return "\n".join(matched) + "\n"


def write_packets_log(mode, scenario, stderr_text):
    """Extract and write packets.log for a scenario."""
    content = extract_packets_log(stderr_text)
    write_fixture(mode, scenario, "packets.log", content)
