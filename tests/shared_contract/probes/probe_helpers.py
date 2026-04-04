"""Shared helpers for golden trace probe scripts."""

import os
import signal
import subprocess

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
