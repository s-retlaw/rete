"""Shared utilities for rete interop tests."""

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


def write_rnsd_config(
    config_dir: str,
    port: int,
    ifac_netname: str = None,
) -> str:
    """Write a minimal rnsd config file. Returns the config dir path.

    Args:
        config_dir: Directory for the config file.
        port: TCP server listen port.
        ifac_netname: Optional IFAC network name.
    """
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")

    ifac_line = ""
    if ifac_netname:
        ifac_line = f"\n    networkname = {ifac_netname}"

    with open(config_path, "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = yes
  share_instance = no

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


# ---------------------------------------------------------------------------
# InteropTest harness — eliminates per-test boilerplate
# ---------------------------------------------------------------------------

class InteropTest:
    """Context manager that handles rnsd/Rust/Python process lifecycle,
    stdout collection, assertion counting, and cleanup.

    Usage::

        with InteropTest("my-test", default_port=4250) as t:
            t.start_rnsd()
            rust = t.start_rust(seed="my-seed-42")
            py = t.start_py_helper(script_text)

            t.wait_for_line(py, "PY_READY")
            t.check(condition, "description of check")

    On exit the harness kills all processes, removes the tmpdir,
    prints pass/fail summary, and calls ``sys.exit(1)`` on failure.
    """

    def __init__(self, name: str, default_port: int, default_timeout: float = 30.0):
        self.name = name
        self._procs = []
        self._stop = threading.Event()
        self.passed = 0
        self.failed = 0
        self._total_checks = 0
        self._rust_proc = None

        parser = argparse.ArgumentParser(description=f"rete {name} interop test")
        parser.add_argument(
            "--rust-binary", default="../../target/debug/rete-linux",
            help="Path to the rete-linux binary",
        )
        parser.add_argument(
            "--port", type=int, default=default_port, help="TCP port for rnsd",
        )
        parser.add_argument(
            "--timeout", type=float, default=default_timeout,
            help="Test timeout in seconds",
        )
        self.args = parser.parse_args()

        self.rust_binary = os.path.abspath(self.args.rust_binary)
        if not os.path.exists(self.rust_binary):
            print(f"FAIL: Rust binary not found at {self.rust_binary}")
            print("  Build it with: cargo build -p rete-example-linux")
            sys.exit(1)

        self.tmpdir = tempfile.mkdtemp(prefix=f"rete_{name.replace('-', '_')}_")
        self.port = self.args.port
        self.timeout = self.args.timeout

    # -- context manager --

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()
        if exc_type is not None:
            return False  # re-raise
        self._print_summary()
        return False

    # -- process helpers --

    def start_rnsd(self, port=None, ifac_netname=None):
        """Start an rnsd transport node and wait for its TCP port."""
        port = port or self.port
        config_dir = os.path.join(self.tmpdir, f"rnsd_config_{port}")
        write_rnsd_config(config_dir, port, ifac_netname=ifac_netname)

        self._log(f"starting rnsd on port {port}...")
        proc = subprocess.Popen(
            [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", config_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)

        if not wait_for_port("127.0.0.1", port, timeout=15.0):
            self._log(f"FAIL: rnsd did not start on port {port} within 15s")
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace")
                print(f"  rnsd stderr:\n{err}")
            sys.exit(1)
        self._log("rnsd is listening")
        return proc

    def start_rust(self, seed, port=None, extra_args=None):
        """Start the Rust rete-linux node and return its stdout line list.

        Args:
            seed: Identity seed string (``--identity-seed``).
            port: TCP port to connect to (defaults to ``self.port``).
            extra_args: Additional CLI args (e.g. ``["--transport"]``).

        Returns:
            list[str]: A live-updated list of stdout lines.
        """
        port = port or self.port
        cmd = [
            self.rust_binary,
            "--connect", f"127.0.0.1:{port}",
            "--identity-seed", seed,
        ]
        if extra_args:
            cmd.extend(extra_args)

        self._log("starting Rust node...")
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)
        self._rust_proc = proc

        lines = []
        t = threading.Thread(target=read_stdout_lines, args=(proc, lines, self._stop), daemon=True)
        t.start()
        return lines

    def start_py_helper(self, script: str):
        """Write *script* to a temp file, run it, and return its stdout line list."""
        path = os.path.join(self.tmpdir, f"py_helper_{len(self._procs)}.py")
        with open(path, "w") as f:
            f.write(script)

        self._log("starting Python helper...")
        proc = subprocess.Popen(
            [sys.executable, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)

        lines = []
        t = threading.Thread(target=read_stdout_lines, args=(proc, lines, self._stop), daemon=True)
        t.start()
        return lines

    def py_rns_config(self, port=None, transport=False):
        """Return a Python RNS config string that connects as a TCP client."""
        port = port or self.port
        transport_str = "yes" if transport else "no"
        return f"""\
[reticulum]
  enable_transport = {transport_str}
  share_instance = no

[logging]
  loglevel = 5

[interfaces]

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port}
"""

    # -- waiting / polling --

    def wait_for_line(self, lines, prefix, timeout=None):
        """Poll *lines* for one starting with *prefix*. Returns the value after
        the prefix (split on first ``:``) or ``None`` on timeout."""
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            for line in lines:
                if line.startswith(prefix):
                    _, _, value = line.partition(":")
                    return value.strip() if value else ""
            time.sleep(0.3)
        return None

    def has_line(self, lines, prefix, contains=None):
        """Check if any line starts with *prefix* (and optionally contains *contains*)."""
        for line in lines:
            if line.startswith(prefix):
                if contains is None or contains in line:
                    return True
        return False

    def send_rust(self, command):
        """Write a command to the Rust node's stdin."""
        if self._rust_proc and self._rust_proc.stdin:
            self._rust_proc.stdin.write(f"{command}\n".encode())
            self._rust_proc.stdin.flush()

    # -- assertions --

    def check(self, condition, description, detail=None):
        """Record a pass/fail assertion."""
        self._total_checks += 1
        idx = self._total_checks
        if condition:
            self._log(f"PASS [{idx}]: {description}")
            self.passed += 1
        else:
            self._log(f"FAIL [{idx}]: {description}")
            if detail:
                print(f"  {detail}")
            self.failed += 1

    # -- output collection --

    def collect_rust_stderr(self, last_chars=1000):
        """Terminate the Rust node and return its stderr (last *last_chars*)."""
        if not self._rust_proc:
            return ""
        self._stop.set()
        self._rust_proc.send_signal(signal.SIGTERM)
        try:
            _, stderr = self._rust_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self._rust_proc.kill()
            _, stderr = self._rust_proc.communicate()
        return stderr.decode(errors="replace")[-last_chars:]

    def dump_output(self, label, lines):
        """Print collected output lines."""
        print(f"[{self.name}] {label}:")
        for line in lines:
            if line.strip():
                print(f"  {line}")

    # -- internals --

    def _log(self, msg):
        print(f"[{self.name}] {msg}")

    def _cleanup(self):
        self._log("cleaning up...")
        self._stop.set()
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=5)
            except Exception:
                pass
        try:
            shutil.rmtree(self.tmpdir)
        except Exception:
            pass

    def _print_summary(self):
        total = self.passed + self.failed
        print(f"\n[{self.name}] Results: {self.passed}/{total} passed, {self.failed}/{total} failed")
        if self.failed > 0:
            sys.exit(1)
        else:
            self._log("ALL TESTS PASSED")
            sys.exit(0)
