"""Docker Compose test orchestrator for rete topology tests.

Extends the interop_helpers.py patterns to manage Docker Compose stacks
instead of local subprocesses. Each test starts a compose topology,
streams container logs, runs assertions, and tears down.
"""

import os
import subprocess
import sys
import tempfile
import threading
import time

# Resolve paths relative to this file
_INTEROP_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_INTEROP_DIR, "..", ".."))
_TOPOLOGIES_DIR = os.path.join(_REPO_ROOT, "tests", "docker", "topologies")


class DockerTopologyTest:
    """Context manager for Docker Compose-based interop tests.

    Usage::

        with DockerTopologyTest("auto-2node", "auto-2node.yml") as t:
            t.start()
            t.wait_for_line("rust-node", "IDENTITY:", timeout=30)
            t.wait_for_line("python-node", "PY_DISCOVERED:", timeout=30)
            t.check(True, "Peers discovered each other")
    """

    def __init__(self, name: str, compose_file: str, timeout: float = 60.0):
        self.name = name
        self.compose_file = os.path.join(_TOPOLOGIES_DIR, compose_file)
        self.timeout = timeout
        self.project_name = f"rete-test-{name}-{os.getpid()}"
        self.passed = 0
        self.failed = 0
        self._total_checks = 0
        self._stop = threading.Event()
        self._log_threads = []
        self._service_lines: dict[str, list[str]] = {}
        self._stdin_pipes: dict[str, subprocess.Popen] = {}
        self._started = False

        if not os.path.exists(self.compose_file):
            print(f"FAIL: compose file not found: {self.compose_file}")
            sys.exit(1)

        # Verify binary exists
        binary = os.path.join(_REPO_ROOT, "target", "debug", "rete-linux")
        if not os.path.exists(binary):
            print(f"FAIL: rete-linux binary not found at {binary}")
            print("  Build it with: cargo build -p rete-example-linux")
            sys.exit(1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()
        if exc_type is not None:
            return False
        self._print_summary()
        return False

    # -- lifecycle --

    def start(self, env: dict[str, str] | None = None):
        """Start the compose stack and begin streaming logs."""
        self._log("starting compose stack...")
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)

        # Build images if needed, then start
        result = subprocess.run(
            ["docker", "compose", "-f", self.compose_file,
             "-p", self.project_name, "up", "-d", "--build"],
            cwd=_REPO_ROOT,
            env=cmd_env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            self._log(f"compose up failed:\n{result.stderr}")
            sys.exit(1)

        self._started = True
        self._log("compose stack running")

        # Discover services and start log streaming for each
        services = self._list_services()
        for svc in services:
            self._start_log_stream(svc)

    def _list_services(self) -> list[str]:
        """List service names in the compose stack."""
        result = subprocess.run(
            ["docker", "compose", "-f", self.compose_file,
             "-p", self.project_name, "ps", "--services"],
            capture_output=True, text=True,
        )
        return [s.strip() for s in result.stdout.strip().split("\n") if s.strip()]

    def _start_log_stream(self, service: str):
        """Start a background thread streaming logs from a service."""
        lines: list[str] = []
        self._service_lines[service] = lines

        def stream():
            proc = subprocess.Popen(
                ["docker", "compose", "-f", self.compose_file,
                 "-p", self.project_name, "logs", "-f", "--no-log-prefix", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            while not self._stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    break
                decoded = line.decode(errors="replace").rstrip("\n")
                if decoded:
                    lines.append(decoded)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        t = threading.Thread(target=stream, daemon=True)
        t.start()
        self._log_threads.append(t)

    # -- assertions --

    def check(self, condition: bool, description: str, detail: str | None = None):
        """Record a test assertion (same pattern as InteropTest)."""
        self._total_checks += 1
        if condition:
            self.passed += 1
            print(f"[{self.name}] PASS [{self._total_checks}]: {description}")
        else:
            self.failed += 1
            msg = f"[{self.name}] FAIL [{self._total_checks}]: {description}"
            if detail:
                msg += f" ({detail})"
            print(msg)

    # -- log queries --

    def get_lines(self, service: str) -> list[str]:
        """Return all collected log lines for a service."""
        return self._service_lines.get(service, [])

    def wait_for_line(
        self, service: str, prefix: str, timeout: float | None = None
    ) -> str | None:
        """Wait for a log line starting with prefix. Returns the full line or None."""
        timeout = timeout or self.timeout
        lines = self._service_lines.setdefault(service, [])
        deadline = time.monotonic() + timeout
        seen = 0
        while time.monotonic() < deadline:
            while seen < len(lines):
                if lines[seen].startswith(prefix) or prefix in lines[seen]:
                    return lines[seen]
                seen += 1
            time.sleep(0.3)
        return None

    def has_line(self, service: str, prefix: str) -> bool:
        """Check if any collected line contains the prefix."""
        return any(prefix in line for line in self.get_lines(service))

    # -- output --

    def dump_logs(self, service: str, label: str | None = None):
        """Print all collected lines for a service."""
        label = label or service
        lines = self.get_lines(service)
        print(f"[{self.name}] {label} output ({len(lines)} lines):")
        for line in lines:
            print(f"  {line}")

    def _log(self, msg: str):
        print(f"[{self.name}] {msg}", flush=True)

    def _print_summary(self):
        total = self.passed + self.failed
        print(f"[{self.name}] cleaning up...")
        print()
        print(f"[{self.name}] Results: {self.passed}/{total} passed, {self.failed}/{total} failed")
        if self.failed == 0:
            print(f"[{self.name}] ALL TESTS PASSED")
        else:
            print(f"[{self.name}] SOME TESTS FAILED")
            sys.exit(1)

    # -- container management --

    def _get_container_id(self, service: str) -> str:
        """Get the Docker container ID for a running service."""
        result = subprocess.run(
            ["docker", "compose", "-f", self.compose_file,
             "-p", self.project_name, "ps", "-q", service],
            capture_output=True, text=True,
        )
        return result.stdout.strip()

    def send_to_stdin(self, service: str, text: str):
        """Send a line of text to a running container's stdin.

        The compose service must have ``stdin_open: true``.  Uses a
        persistent ``docker attach`` pipe per service.
        """
        if service not in self._stdin_pipes:
            container_id = self._get_container_id(service)
            if not container_id:
                self._log(f"WARNING: no container found for {service}")
                return
            proc = subprocess.Popen(
                ["docker", "attach", "--sig-proxy=false", container_id],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._stdin_pipes[service] = proc

        pipe = self._stdin_pipes[service]
        try:
            pipe.stdin.write(f"{text}\n".encode())
            pipe.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            self._log(f"WARNING: stdin pipe broken for {service}: {e}")

    def stop_service(self, service: str):
        """Stop a single service without tearing down the stack."""
        subprocess.run(
            ["docker", "compose", "-f", self.compose_file,
             "-p", self.project_name, "stop", "-t", "5", service],
            capture_output=True, timeout=15,
        )

    def up_service(self, service: str, env: dict[str, str] | None = None):
        """Bring up a specific service (possibly for the first time)."""
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        subprocess.run(
            ["docker", "compose", "-f", self.compose_file,
             "-p", self.project_name, "up", "-d", service],
            cwd=_REPO_ROOT,
            env=cmd_env,
            capture_output=True,
            timeout=30,
        )
        # Reset log lines for this service and start streaming
        self._service_lines[service] = []
        self._start_log_stream(service)

    def get_host_port(self, service: str, container_port: int) -> int | None:
        """Get the host-mapped port for a container's published port."""
        result = subprocess.run(
            ["docker", "compose", "-f", self.compose_file,
             "-p", self.project_name, "port", service, str(container_port)],
            capture_output=True, text=True,
        )
        output = result.stdout.strip()
        if not output:
            return None
        _, _, port_str = output.rpartition(":")
        return int(port_str)

    # -- cleanup --

    def _cleanup(self):
        self._stop.set()
        for pipe in self._stdin_pipes.values():
            try:
                pipe.stdin.close()
                pipe.terminate()
                pipe.wait(timeout=3)
            except Exception:
                pass
        self._stdin_pipes.clear()
        if self._started:
            self._log("tearing down compose stack...")
            subprocess.run(
                ["docker", "compose", "-f", self.compose_file,
                 "-p", self.project_name, "down", "-v",
                 "--rmi", "local", "--remove-orphans", "--timeout", "5"],
                capture_output=True,
                timeout=30,
            )
        for t in self._log_threads:
            t.join(timeout=3)
