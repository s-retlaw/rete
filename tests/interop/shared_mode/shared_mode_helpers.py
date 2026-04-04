"""Helpers for shared-mode E2E tests against the Rust rete-shared daemon."""

import json
import os
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_RUST_BINARY = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "target", "debug", "rete-shared"
)
DAEMON_READY = "DAEMON_READY"


# ---------------------------------------------------------------------------
# Daemon lifecycle
# ---------------------------------------------------------------------------

def start_rete_shared(
    data_dir,
    rust_binary=None,
    instance_name="default",
    instance_type="unix",
    transport=False,
    timeout_secs=10,
):
    """Start rete-shared and wait for DAEMON_READY.

    Returns the subprocess.Popen object.
    Raises RuntimeError if daemon fails to start within timeout_secs.
    """
    binary = rust_binary or DEFAULT_RUST_BINARY
    if not os.path.isfile(binary):
        raise FileNotFoundError(f"rete-shared binary not found: {binary}")

    cmd = [
        binary,
        "--data-dir", data_dir,
        "--instance-name", instance_name,
        "--shared-instance-type", instance_type,
    ]
    if transport:
        cmd.append("--transport")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            raise RuntimeError(
                f"rete-shared exited early (rc={proc.returncode}): "
                f"{stderr.decode(errors='replace')[-500:]}"
            )
        line = _readline_timeout(proc.stdout, deadline - time.monotonic())
        if line and DAEMON_READY in line:
            return proc

    proc.kill()
    _, stderr = proc.communicate()
    raise RuntimeError(
        f"rete-shared did not emit DAEMON_READY within {timeout_secs}s: "
        f"{stderr.decode(errors='replace')[-500:]}"
    )


def stop_daemon(proc, timeout_secs=5):
    """Send SIGTERM and wait for clean shutdown, fallback to SIGKILL."""
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout_secs)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _readline_timeout(stream, timeout):
    """Read one line from a stream with a timeout."""
    ready, _, _ = select.select([stream], [], [], max(0, timeout))
    if ready:
        line = stream.readline()
        if line:
            return line.decode(errors="replace").strip()
    return None


# ---------------------------------------------------------------------------
# Client config
# ---------------------------------------------------------------------------

def write_shared_client_config(config_dir, mode="unix", ports=None):
    """Write a minimal Python RNS shared-mode client config.

    For Unix mode, only share_instance=Yes is needed.
    For TCP mode, shared_instance_port must be set.
    """
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")
    if mode == "unix":
        content = "[reticulum]\n  share_instance = Yes\n  enable_transport = No\n"
    else:
        data_port = (ports or {}).get("data_port", 37428)
        ctrl_port = (ports or {}).get("ctrl_port", 37429)
        content = (
            f"[reticulum]\n"
            f"  share_instance = Yes\n"
            f"  shared_instance_port = {data_port}\n"
            f"  instance_control_port = {ctrl_port}\n"
            f"  enable_transport = No\n"
        )
    with open(config_path, "w") as f:
        f.write(content)
    return config_path


# ---------------------------------------------------------------------------
# Python client subprocess
# ---------------------------------------------------------------------------

CLIENT_ATTACH_SCRIPT = textwrap.dedent("""\
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

CLIENT_CRASH_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]

t0 = time.time()
rns = RNS.Reticulum(configdir=config_dir)
attach_time = time.time() - t0
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       app_name, aspect)
dest.announce()
time.sleep(1)

result = {
    "attached": attached,
    "attach_time": round(attach_time, 3),
    "dest_hash": dest.hash.hex(),
}

with open(result_file, "w") as f:
    json.dump(result, f)

# Exit abruptly — no exit_handler(), simulating a crash.
os._exit(0)
""")


def run_shared_client(script, args):
    """Run a Python client script in a subprocess. Returns Popen."""
    return subprocess.Popen(
        [sys.executable, "-c", script] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_client(proc, timeout=30):
    """Wait for a client subprocess to finish. Returns (stdout, stderr)."""
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        return stdout.decode(errors="replace"), stderr.decode(errors="replace")


def read_result(path):
    """Read JSON result written by a client subprocess."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"  [WARN] corrupt result file {path}: {e}")
        return None


# ---------------------------------------------------------------------------
# Test result reporting
# ---------------------------------------------------------------------------

class SharedModeTest:
    """Simple test runner for shared-mode E2E tests."""

    def __init__(self, name, rust_binary=None):
        self.name = name
        self.rust_binary = rust_binary
        self.checks = []
        self.tmpdir = tempfile.mkdtemp(prefix=f"rete_shared_{name}_")
        self.daemon_proc = None

    def start_daemon(self, instance_name="default", instance_type="unix", transport=False):
        data_dir = os.path.join(self.tmpdir, "daemon_data")
        os.makedirs(data_dir, exist_ok=True)
        self.daemon_proc = start_rete_shared(
            data_dir=data_dir,
            rust_binary=self.rust_binary,
            instance_name=instance_name,
            instance_type=instance_type,
            transport=transport,
        )
        self.check(
            self.daemon_proc.poll() is None,
            "Daemon started and DAEMON_READY received",
        )
        return self.daemon_proc

    def make_client_dir(self, name):
        d = os.path.join(self.tmpdir, name)
        os.makedirs(d, exist_ok=True)
        write_shared_client_config(d, mode="unix")
        return d

    def check(self, condition, description):
        status = "PASS" if condition else "FAIL"
        self.checks.append((status, description))
        print(f"  [{status}] {description}")

    def finish(self):
        if self.daemon_proc:
            stop_daemon(self.daemon_proc)
        passed = sum(1 for s, _ in self.checks if s == "PASS")
        total = len(self.checks)
        print(f"\n{self.name}: {passed}/{total} checks passed")
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        if passed < total:
            print("FAILED")
            sys.exit(1)
        else:
            print("OK")


def parse_args():
    """Parse --rust-binary and --timeout from sys.argv."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-binary", default=DEFAULT_RUST_BINARY)
    parser.add_argument("--timeout", type=int, default=30)
    return parser.parse_args()
