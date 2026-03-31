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
    share_instance: bool = False,
) -> str:
    """Write a minimal rnsd config file. Returns the config dir path.

    Args:
        config_dir: Directory for the config file.
        port: TCP server listen port.
        ifac_netname: Optional IFAC network name.
        share_instance: Enable shared instance (needed for multi-hop link relay).
    """
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "config")

    ifac_line = ""
    if ifac_netname:
        ifac_line = f"\n    networkname = {ifac_netname}"

    share_val = "yes" if share_instance else "no"
    with open(config_path, "w") as f:
        f.write(f"""\
[reticulum]
  enable_transport = yes
  share_instance = {share_val}

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
            rust = t.start_rust()
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
        self.skipped = 0
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
        parser.add_argument(
            "--serial-port", default="/dev/ttyUSB0",
            help="Serial port for ESP32 tests (default: /dev/ttyUSB0)",
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

    def start_rnsd(self, port=None, ifac_netname=None, share_instance=False):
        """Start an rnsd transport node and wait for its TCP port."""
        port = port or self.port
        config_dir = os.path.join(self.tmpdir, f"rnsd_config_{port}")
        write_rnsd_config(config_dir, port, ifac_netname=ifac_netname, share_instance=share_instance)

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

    def start_rust(self, port=None, extra_args=None):
        """Start the Rust rete-linux node and return its stdout line list.

        Args:
            port: TCP port to connect to (defaults to ``self.port``).
            extra_args: Additional CLI args (e.g. ``["--transport"]``).

        Returns:
            list[str]: A live-updated list of stdout lines.
        """
        port = port or self.port
        # Each Rust process gets an isolated data dir (identity + snapshot)
        data_dir = os.path.join(self.tmpdir, f"rete_data_{len(self._procs)}")
        os.makedirs(data_dir, exist_ok=True)
        cmd = [
            self.rust_binary,
            "--data-dir", data_dir,
            "--connect", f"127.0.0.1:{port}",
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
    ingress_control = false
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

    def wait_for_line_after(self, lines, prefix, after_index, timeout=None):
        """Like wait_for_line but only searches lines added after *after_index*."""
        deadline = time.time() + (timeout or self.timeout)
        while time.time() < deadline:
            for line in lines[after_index:]:
                if line.startswith(prefix):
                    _, _, value = line.partition(":")
                    return value.strip() if value else ""
            time.sleep(0.3)
        return None

    def discover_esp32_dest(self, rust_lines, timeout=15):
        """Wait for an ANNOUNCE line in rete-linux stdout and return the dest hash.

        rete-linux logs ``ANNOUNCE:<dest_hash>:<identity_hash>:<hops>`` to stdout
        when it receives an announce from a peer. This method returns the first
        announce dest_hash that is NOT the rete-linux node's own destination.
        """
        own_dest = None
        for line in rust_lines:
            if line.startswith("IDENTITY:"):
                _, _, v = line.partition(":")
                own_dest = v.strip()
                break

        deadline = time.time() + timeout
        while time.time() < deadline:
            for line in rust_lines:
                if line.startswith("ANNOUNCE:"):
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        dest = parts[1]
                        if dest != own_dest:
                            self._log(f"discovered ESP32 dest: {dest}")
                            return dest
            time.sleep(0.3)
        self._log("FAIL: timed out waiting for ESP32 announce")
        return None

    def establish_esp32_link(self, rust_lines, dest_hash, after_index=0, timeout=15):
        """Initiate a link and return (link_id, success). Waits for LINK_ESTABLISHED."""
        self._log(f"initiating link to {dest_hash}...")
        self.send_rust(f"link {dest_hash}")
        link_line = self.wait_for_line_after(
            rust_lines, "LINK_ESTABLISHED", after_index, timeout=timeout,
        )
        if link_line is None:
            return None, False
        link_id = link_line.strip()
        self._log(f"link_id: {link_id}")
        time.sleep(2.0)  # LRRTT handshake stabilization
        return link_id, True

    def close_esp32_link(self, link_id, rust_lines=None, timeout=5):
        """Send close command and wait for cleanup.

        If *rust_lines* is provided, polls for LINK_CLOSED confirmation.
        Otherwise falls back to a fixed 2s sleep.
        """
        self._log(f"closing link {link_id}...")
        self.send_rust(f"close {link_id}")
        if rust_lines is not None:
            result = self.wait_for_line(rust_lines, "LINK_CLOSED", timeout=timeout)
            if result is None:
                self._log("warning: LINK_CLOSED not seen within timeout")
                time.sleep(1.0)
        else:
            time.sleep(2.0)

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

    # -- discovery --

    def discover_esp32_path(self, our_dest, app_name, aspects, timeout=None):
        """Discover an ESP32 destination from the RNS path_table.

        Polls ``RNS.Transport.path_table`` for entries whose recalled
        identity, combined with *app_name*/*aspects*, reconstructs to
        the same destination hash.  This filters out secondary
        destinations (e.g. ``rete/test/secondary``) that share the
        same identity but have different aspects.

        Returns the destination hash (bytes) or ``None`` on timeout.
        """
        import RNS
        timeout = timeout or self.timeout
        self._log("waiting for ESP32 announce (path discovery)...")
        deadline = time.time() + timeout
        while time.time() < deadline:
            for h in list(RNS.Transport.path_table):
                if h == our_dest.hash:
                    continue
                recalled = RNS.Identity.recall(h)
                if recalled:
                    candidate = RNS.Destination(
                        recalled, RNS.Destination.OUT,
                        RNS.Destination.SINGLE, app_name, *aspects,
                    )
                    if candidate.hash == h:
                        self._log(f"discovered ESP32 dest hash: {h.hex()}")
                        return h
            time.sleep(0.5)
        return None

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

    def skip(self, description, reason):
        """Record a skipped check with an explanation."""
        self.skipped += 1
        self._log(f"SKIP: {description} — {reason}")

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
        skip_str = f", {self.skipped} skipped" if self.skipped else ""
        print(f"\n[{self.name}] Results: {self.passed}/{total} passed, {self.failed}/{total} failed{skip_str}")
        if self.failed > 0:
            sys.exit(1)
        else:
            self._log("ALL TESTS PASSED")
            sys.exit(0)

    def start_rust_dual(self, port=None, serial_port=None, extra_args=None):
        """Start rete-linux with both --connect (TCP) and --serial (multi-interface).

        Args:
            port: TCP port to connect to (defaults to ``self.port``).
            serial_port: Serial port (defaults to ``--serial-port`` arg).
            extra_args: Additional CLI args (e.g. ``["--transport"]``).

        Returns:
            list[str]: A live-updated list of stdout lines.
        """
        port = port or self.port
        serial_port = serial_port or self.args.serial_port
        data_dir = os.path.join(self.tmpdir, f"rete_data_{len(self._procs)}")
        os.makedirs(data_dir, exist_ok=True)
        cmd = [
            self.rust_binary,
            "--data-dir", data_dir,
            "--connect", f"127.0.0.1:{port}",
            "--serial", serial_port,
        ]
        if extra_args:
            cmd.extend(extra_args)

        self._log(f"starting Rust dual node (TCP:{port} + serial:{serial_port})...")
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)
        self._rust_proc = proc

        lines = []
        t = threading.Thread(target=read_stdout_lines, args=(proc, lines, self._stop), daemon=True)
        t.start()
        return lines

    # -- ESP32 serial helpers --

    def start_diag_serial_bridge(self, tcp_port, serial_port=None, baud=115200):
        """Launch serial_bridge_diag.py and wait for TCP port to accept connections.

        Like start_serial_bridge() but also decodes and logs every HDLC
        frame as parsed RNS packets to stderr.

        Returns the bridge process.
        """
        serial_port = serial_port or self.args.serial_port
        bridge_script = os.path.join(os.path.dirname(__file__), "serial_bridge_diag.py")
        cmd = [
            sys.executable, bridge_script,
            "--serial-port", serial_port,
            "--baud", str(baud),
            "--tcp-port", str(tcp_port),
        ]
        self._log(f"starting diagnostic serial bridge on TCP port {tcp_port}...")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)

        if not wait_for_port("127.0.0.1", tcp_port, timeout=10.0):
            self._log(f"FAIL: diagnostic serial bridge did not start on port {tcp_port}")
            sys.exit(1)
        self._log("diagnostic serial bridge is listening")
        return proc

    def start_serial_bridge(self, tcp_port, serial_port=None, baud=115200):
        """Launch serial_bridge.py and wait for TCP port to accept connections.

        Returns the bridge process.
        """
        serial_port = serial_port or self.args.serial_port
        bridge_script = os.path.join(os.path.dirname(__file__), "serial_bridge.py")
        cmd = [
            sys.executable, bridge_script,
            "--serial-port", serial_port,
            "--baud", str(baud),
            "--tcp-port", str(tcp_port),
        ]
        self._log(f"starting serial bridge on TCP port {tcp_port}...")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)

        if not wait_for_port("127.0.0.1", tcp_port, timeout=10.0):
            self._log(f"FAIL: serial bridge did not start on port {tcp_port}")
            sys.exit(1)
        self._log("serial bridge is listening")
        return proc

    def start_rust_serial_bridge(self, tcp_port, serial_port=None, baud=115200):
        """Launch the Rust rete-serial-bridge binary and wait for TCP port.

        The binary path is derived from the same target/debug directory as
        the main rust_binary.

        Returns the bridge process.
        """
        serial_port = serial_port or self.args.serial_port
        bridge_bin = os.path.join(
            os.path.dirname(self.rust_binary), "rete-serial-bridge",
        )
        if not os.path.exists(bridge_bin):
            self._log(f"FAIL: Rust serial bridge not found at {bridge_bin}")
            self._log("  Build it with: cargo build -p rete-example-linux")
            sys.exit(1)

        cmd = [
            bridge_bin,
            "--serial-port", serial_port,
            "--baud", str(baud),
            "--tcp-port", str(tcp_port),
        ]
        self._log(f"starting Rust serial bridge on TCP port {tcp_port}...")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)

        if not wait_for_port("127.0.0.1", tcp_port, timeout=10.0):
            self._log(f"FAIL: Rust serial bridge did not start on port {tcp_port}")
            sys.exit(1)
        self._log("Rust serial bridge is listening")
        return proc

    def start_rust_serial(self, serial_port=None, extra_args=None):
        """Start the Rust rete-linux node with --serial and return its stdout line list.

        Args:
            serial_port: Serial port to connect to (defaults to ``--serial-port`` arg).
            extra_args: Additional CLI args (e.g. ``["--transport"]``).

        Returns:
            list[str]: A live-updated list of stdout lines.
        """
        serial_port = serial_port or self.args.serial_port
        data_dir = os.path.join(self.tmpdir, f"rete_data_{len(self._procs)}")
        os.makedirs(data_dir, exist_ok=True)
        cmd = [
            self.rust_binary,
            "--data-dir", data_dir,
            "--serial", serial_port,
        ]
        if extra_args:
            cmd.extend(extra_args)

        self._log(f"starting Rust serial node on {serial_port}...")
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)
        self._rust_proc = proc

        lines = []
        t = threading.Thread(target=read_stdout_lines, args=(proc, lines, self._stop), daemon=True)
        t.start()
        return lines

    def start_tcp_proxy(self, listen_port, target_port):
        """Launch rns_proxy.py between listen_port and target_port.

        Returns the proxy process. Packet logs go to the process's stderr.
        """
        proxy_script = os.path.join(os.path.dirname(__file__), "rns_proxy.py")
        cmd = [
            sys.executable, proxy_script,
            "--listen", str(listen_port),
            "--target", str(target_port),
        ]
        self._log(f"starting TCP proxy {listen_port} -> {target_port}...")
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)

        if not wait_for_port("127.0.0.1", listen_port, timeout=10.0):
            self._log(f"FAIL: TCP proxy did not start on port {listen_port}")
            sys.exit(1)
        self._log(f"TCP proxy listening on {listen_port}")
        return proc
