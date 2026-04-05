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

DEFAULT_RUST_BINARY = os.environ.get(
    "RETE_BINARY",
    os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "target", "debug", "rete-shared"
    ),
)
DAEMON_READY = "DAEMON_READY"

# When running inside a container (RETE_CONTAINERIZED=1), each test has its
# own network namespace so fixed ports are safe — no PID-based offsets needed.
IS_CONTAINERIZED = os.environ.get("RETE_CONTAINERIZED") == "1"
CONTAINER_DATA_PORT = 37428
CONTAINER_CTRL_PORT = 37429


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
    port=None,
    control_port=None,
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
    if port is not None:
        cmd.extend(["--shared-instance-port", str(port)])
    if control_port is not None:
        cmd.extend(["--instance-control-port", str(control_port)])
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
            f"  shared_instance_type = tcp\n"
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

CLIENT_ANNOUNCE_AND_POLL = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
wait_secs = int(sys.argv[5])
poll_hash_hex = sys.argv[6] if len(sys.argv) > 6 else ""

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       app_name, aspect)
dest.announce()

seen_hash = False
if poll_hash_hex:
    target = bytes.fromhex(poll_hash_hex)
    for _ in range(wait_secs * 10):
        time.sleep(0.1)
        if RNS.Transport.has_path(target):
            seen_hash = True
            break
        if hasattr(RNS.Transport, 'announce_table'):
            if target in RNS.Transport.announce_table:
                seen_hash = True
                break
else:
    time.sleep(wait_secs)

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "identity_hash": identity.hexhash,
    "seen_target": seen_hash,
}

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")


def tcp_ports():
    """Return (data_port, ctrl_port) for TCP tests.

    Inside a container (RETE_CONTAINERIZED=1), returns fixed ports.
    On the host, returns PID-offset ports for backward compatibility.
    """
    if IS_CONTAINERIZED:
        return CONTAINER_DATA_PORT, CONTAINER_CTRL_PORT
    base = 49000 + (os.getpid() % 1000)
    return base, base + 1


# ---------------------------------------------------------------------------
# EPIC-08 client script templates (two-client peer-to-peer through daemon)
#
# Key shared-mode constraint: RNS.Transport.has_path() returns False in
# shared-mode clients because the daemon owns transport. However,
# RNS.Identity.recall() works after announce delivery. Scripts poll
# Identity.recall() instead of has_path().
#
# Ready file pattern: receiver scripts write a JSON ready file with their
# dest_hash immediately after creating the destination and announcing.
# The test runner reads this file to coordinate sender startup.
# ---------------------------------------------------------------------------

CLIENT_RECEIVER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time, threading
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
wait_secs = int(sys.argv[5])
ready_file = sys.argv[6] if len(sys.argv) > 6 else ""

received_data = []
lock = threading.Lock()

def packet_callback(data, packet):
    with lock:
        received_data.append(data)

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       app_name, aspect)
dest.set_packet_callback(packet_callback)
dest.announce()

# Write ready file so the test runner knows our dest_hash
if ready_file:
    with open(ready_file, "w") as f:
        json.dump({"dest_hash": dest.hash.hex(), "identity_hash": identity.hexhash}, f)

time.sleep(wait_secs)

with lock:
    got = [d.hex() if isinstance(d, bytes) else str(d) for d in received_data]

result = {
    "attached": attached,
    "dest_hash": dest.hash.hex(),
    "identity_hash": identity.hexhash,
    "received_count": len(got),
    "received_data": got,
}

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")

CLIENT_SENDER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
target_hash_hex = sys.argv[5]
payload_hex = sys.argv[6]
wait_secs = int(sys.argv[7])

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

target_hash = bytes.fromhex(target_hash_hex)

# In shared mode, has_path() returns False (daemon owns transport).
# Poll Identity.recall() instead — it works after the daemon relays
# the announce to us.
identity_found = False
target_identity = None
for _ in range(wait_secs * 10):
    target_identity = RNS.Identity.recall(target_hash)
    if target_identity:
        identity_found = True
        break
    time.sleep(0.1)

sent = False
if identity_found:
    dest = RNS.Destination(target_identity, RNS.Destination.OUT,
                           RNS.Destination.SINGLE, app_name, aspect)
    payload = bytes.fromhex(payload_hex)
    pkt = RNS.Packet(dest, payload)
    receipt = pkt.send()
    sent = receipt is not None
    time.sleep(1)

result = {
    "attached": attached,
    "identity_found": identity_found,
    "sent": sent,
}

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")

CLIENT_LINK_SERVER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time, threading
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
wait_secs = int(sys.argv[5])
mode = sys.argv[6] if len(sys.argv) > 6 else "echo"
ready_file = sys.argv[7] if len(sys.argv) > 7 else ""

lock = threading.Lock()
state = {
    "link_established": False,
    "link_data_received": [],
    "link_closed": False,
    "request_received": False,
    "request_path": None,
    "resource_completed": False,
    "resource_data_hex": None,
    "resource_size": 0,
}

def link_established(link):
    with lock:
        state["link_established"] = True
    link.set_link_closed_callback(link_closed)
    link.set_packet_callback(link_data_callback)
    if mode in ("resource", "resource_large"):
        link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
        link.set_resource_started_callback(resource_started)
        link.set_resource_concluded_callback(resource_concluded)

def link_closed(link):
    with lock:
        state["link_closed"] = True

def link_data_callback(message, packet):
    with lock:
        state["link_data_received"].append(
            message.hex() if isinstance(message, bytes) else str(message)
        )

def request_handler(path, data, request_id, link_id, remote_identity, requested_at):
    with lock:
        state["request_received"] = True
        state["request_path"] = path
    return {"echo": data, "server": "rete-shared"}

def resource_started(resource):
    pass

def resource_concluded(resource):
    with lock:
        if resource.status == RNS.Resource.COMPLETE:
            data = resource.data.read()
            state["resource_completed"] = True
            state["resource_data_hex"] = data.hex()
            state["resource_size"] = len(data)

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       app_name, aspect)
dest.set_link_established_callback(link_established)
if mode == "request":
    dest.register_request_handler("/test", request_handler, allow=RNS.Destination.ALLOW_ALL)
dest.announce()

# Write ready file so the test runner knows our dest_hash
if ready_file:
    with open(ready_file, "w") as f:
        json.dump({"dest_hash": dest.hash.hex(), "identity_hash": identity.hexhash}, f)

time.sleep(wait_secs)

with lock:
    result = {
        "attached": attached,
        "dest_hash": dest.hash.hex(),
        "identity_hash": identity.hexhash,
    }
    result.update(state)

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")

CLIENT_LINK_CLIENT_SCRIPT = textwrap.dedent("""\
import json, os, sys, time, io, threading
import RNS

config_dir = sys.argv[1]
result_file = sys.argv[2]
app_name = sys.argv[3]
aspect = sys.argv[4]
target_hash_hex = sys.argv[5]
wait_secs = int(sys.argv[6])
mode = sys.argv[7] if len(sys.argv) > 7 else "echo"
payload_arg = sys.argv[8] if len(sys.argv) > 8 else "48656c6c6f"
# Support @filepath for large payloads that exceed command-line limits
if payload_arg.startswith("@"):
    with open(payload_arg[1:], "rb") as _pf:
        payload_hex = _pf.read().hex()
else:
    payload_hex = payload_arg

lock = threading.Lock()
state = {
    "link_established": False,
    "link_data_received": [],
    "link_closed": False,
    "request_response": None,
    "resource_sent": False,
}

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

target_hash = bytes.fromhex(target_hash_hex)

# In shared mode, has_path() returns False. Poll Identity.recall() instead.
identity_found = False
target_identity = None
for _ in range(wait_secs * 10):
    target_identity = RNS.Identity.recall(target_hash)
    if target_identity:
        identity_found = True
        break
    time.sleep(0.1)

if identity_found:
    dest = RNS.Destination(target_identity, RNS.Destination.OUT,
                           RNS.Destination.SINGLE, app_name, aspect)
    link = RNS.Link(dest)

    def established(lnk):
        with lock:
            state["link_established"] = True

    def closed(lnk):
        with lock:
            state["link_closed"] = True

    def packet_cb(message, packet):
        with lock:
            state["link_data_received"].append(
                message.hex() if isinstance(message, bytes) else str(message)
            )

    link.set_link_established_callback(established)
    link.set_link_closed_callback(closed)
    link.set_packet_callback(packet_cb)

    # Wait for link establishment
    for _ in range(wait_secs * 10):
        with lock:
            if state["link_established"]:
                break
        time.sleep(0.1)

    with lock:
        is_established = state["link_established"]

    if is_established:
        payload = bytes.fromhex(payload_hex)
        if mode == "echo":
            pkt = RNS.Packet(link, payload)
            pkt.send()
            time.sleep(2)
        elif mode == "request":
            def response_cb(request_receipt):
                with lock:
                    if request_receipt.response is not None:
                        state["request_response"] = request_receipt.response
            link.request("/test", data=payload_hex, response_callback=response_cb)
            for _ in range(wait_secs * 10):
                with lock:
                    if state["request_response"] is not None:
                        break
                time.sleep(0.1)
        elif mode in ("resource", "resource_large"):
            # Brief delay to ensure server's link_established callback
            # has set ACCEPT_ALL before we send the resource advertisement.
            time.sleep(1)
            import tempfile
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
            tmp.write(payload)
            tmp.close()
            resource_file = open(tmp.name, "rb")
            resource = RNS.Resource(resource_file, link)
            for _ in range(wait_secs * 10):
                if resource.status in (RNS.Resource.COMPLETE, RNS.Resource.FAILED):
                    break
                time.sleep(0.1)
            with lock:
                state["resource_sent"] = (resource.status == RNS.Resource.COMPLETE)
            resource_file.close()
            os.unlink(tmp.name)

        # Clean teardown
        time.sleep(1)
        link.teardown()
        time.sleep(1)

with lock:
    result = {
        "attached": attached,
        "identity_found": identity_found,
    }
    result.update(state)

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")

CLIENT_LXMF_RECEIVER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time, threading
import RNS
import LXMF

config_dir = sys.argv[1]
result_file = sys.argv[2]
wait_secs = int(sys.argv[3])
display_name = sys.argv[4] if len(sys.argv) > 4 else "Receiver"
mode = sys.argv[5] if len(sys.argv) > 5 else "direct"
ready_file = sys.argv[6] if len(sys.argv) > 6 else ""

lock = threading.Lock()
messages_received = []

def delivery_callback(message):
    with lock:
        messages_received.append({
            "title": message.title_as_string() if message.title else "",
            "content": message.content_as_string() if message.content else "",
            "source_hash": message.source_hash.hex() if message.source_hash else "",
        })

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

identity = RNS.Identity()
storage_path = os.path.join(os.path.dirname(result_file), "lxmf_storage")
os.makedirs(storage_path, exist_ok=True)

router = LXMF.LXMRouter(identity=identity, storagepath=storage_path)
lxmf_dest = router.register_delivery_identity(identity, display_name=display_name)
router.register_delivery_callback(delivery_callback)

if mode == "propagation":
    router.enable_propagation()

lxmf_dest.announce()

# Write ready file so the test runner knows our dest_hash
if ready_file:
    with open(ready_file, "w") as f:
        json.dump({"dest_hash": lxmf_dest.hash.hex(), "identity_hash": identity.hexhash}, f)

time.sleep(wait_secs)

with lock:
    result = {
        "attached": attached,
        "dest_hash": lxmf_dest.hash.hex(),
        "identity_hash": identity.hexhash,
        "messages_received": messages_received,
        "message_count": len(messages_received),
    }

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
""")

CLIENT_LXMF_SENDER_SCRIPT = textwrap.dedent("""\
import json, os, sys, time
import RNS
import LXMF

config_dir = sys.argv[1]
result_file = sys.argv[2]
target_hash_hex = sys.argv[3]
title = sys.argv[4]
content = sys.argv[5]
wait_secs = int(sys.argv[6])
delivery_method = sys.argv[7] if len(sys.argv) > 7 else "direct"

rns = RNS.Reticulum(configdir=config_dir)
attached = rns.is_connected_to_shared_instance

# Allow BackboneInterface epoll thread to initialize and receive
# cached announces from the daemon before starting LXMF operations.
time.sleep(5)

identity = RNS.Identity()
storage_path = os.path.join(os.path.dirname(result_file), "lxmf_storage")
os.makedirs(storage_path, exist_ok=True)

router = LXMF.LXMRouter(identity=identity, storagepath=storage_path)
sender_dest = router.register_delivery_identity(identity, display_name="Sender")

target_hash = bytes.fromhex(target_hash_hex)

# In shared mode, has_path() returns False. Poll Identity.recall() instead.
identity_found = False
target_identity = None
for _ in range(wait_secs * 10):
    target_identity = RNS.Identity.recall(target_hash)
    if target_identity:
        identity_found = True
        break
    time.sleep(0.1)

sent = False
delivery_status = "unknown"
if identity_found and target_identity:
    lxmf_dest = RNS.Destination(target_identity, RNS.Destination.OUT,
                                RNS.Destination.SINGLE, "lxmf", "delivery")
    lxm = LXMF.LXMessage(
        lxmf_dest, sender_dest, content,
        title=title,
    )
    if delivery_method == "opportunistic":
        lxm.desired_method = LXMF.LXMessage.OPPORTUNISTIC
    elif delivery_method == "propagated":
        lxm.desired_method = LXMF.LXMessage.PROPAGATED
        lxm.propagation_node = target_hash
    else:
        lxm.desired_method = LXMF.LXMessage.DIRECT

    router.handle_outbound(lxm)

    # Wait for delivery
    for _ in range(wait_secs * 10):
        if lxm.state >= LXMF.LXMessage.SENT:
            sent = True
            break
        if lxm.state == LXMF.LXMessage.FAILED:
            break
        time.sleep(0.1)

    delivery_status = {
        LXMF.LXMessage.GENERATING: "generating",
        LXMF.LXMessage.OUTBOUND: "outbound",
        LXMF.LXMessage.SENDING: "sending",
        LXMF.LXMessage.SENT: "sent",
        LXMF.LXMessage.DELIVERED: "delivered",
        LXMF.LXMessage.FAILED: "failed",
    }.get(lxm.state, f"unknown_{lxm.state}")

result = {
    "attached": attached,
    "identity_found": identity_found,
    "sent": sent,
    "delivery_status": delivery_status,
}

with open(result_file, "w") as f:
    json.dump(result, f)

try:
    rns.exit_handler()
except Exception:
    pass
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


def wait_for_ready_file(path, timeout=10):
    """Wait for a ready file to appear and return its parsed JSON contents.

    Receiver scripts write a ready file with their dest_hash immediately
    after creating their destination and announcing. This lets the test
    runner coordinate sender startup.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.2)
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
        self.data_dir = None

    def start_daemon(self, instance_name="default", instance_type="unix",
                     transport=False, port=None, control_port=None):
        data_dir = os.path.join(self.tmpdir, "daemon_data")
        os.makedirs(data_dir, exist_ok=True)
        self.data_dir = data_dir
        self.daemon_proc = start_rete_shared(
            data_dir=data_dir,
            rust_binary=self.rust_binary,
            instance_name=instance_name,
            instance_type=instance_type,
            transport=transport,
            port=port,
            control_port=control_port,
        )
        self.check(
            self.daemon_proc.poll() is None,
            "Daemon started and DAEMON_READY received",
        )
        return self.daemon_proc

    def restart_daemon(self, **kwargs):
        """Stop and restart the daemon with the same data_dir.

        Accepts the same keyword arguments as start_daemon() to override
        settings, but reuses the data_dir from the original start.
        """
        if self.daemon_proc:
            stop_daemon(self.daemon_proc)
            self.daemon_proc = None
        self.daemon_proc = start_rete_shared(
            data_dir=self.data_dir,
            rust_binary=self.rust_binary,
            **kwargs,
        )
        self.check(
            self.daemon_proc.poll() is None,
            "Daemon restarted and DAEMON_READY received",
        )
        return self.daemon_proc

    def make_client_dir(self, name, mode="unix", ports=None):
        d = os.path.join(self.tmpdir, name)
        os.makedirs(d, exist_ok=True)
        write_shared_client_config(d, mode=mode, ports=ports)
        # Share the daemon's transport identity with clients so RPC auth
        # matches. Python RNS uses storagepath/transport_identity for the
        # rpc_key derivation; both daemon and client must use the same file.
        if self.data_dir:
            daemon_identity = os.path.join(self.data_dir, "identity")
            client_storage = os.path.join(d, "storage")
            os.makedirs(client_storage, exist_ok=True)
            client_identity = os.path.join(client_storage, "transport_identity")
            if os.path.exists(daemon_identity) and not os.path.exists(client_identity):
                shutil.copy2(daemon_identity, client_identity)
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


# ---------------------------------------------------------------------------
# Robustness / soak helpers
# ---------------------------------------------------------------------------

def raw_tcp_connect(host, port):
    """Open a raw TCP socket (no HDLC, no auth). Returns socket object."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    return s


def raw_unix_connect(socket_path):
    """Open a raw Unix domain socket. Returns socket object."""
    import socket
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(socket_path)
    return s


def get_rss_kb(pid):
    """Read VmRSS from /proc/{pid}/status. Returns KB or None."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, PermissionError, ValueError):
        return None
    return None


def start_python_rnsd(data_dir, instance_type="unix", port=None,
                      control_port=None, timeout_secs=10):
    """Start Python rnsd and wait for it to be ready.

    Returns the subprocess.Popen object.
    Raises RuntimeError if rnsd fails to start within timeout_secs.
    """
    config_dir = os.path.join(data_dir, "rnsd_config")
    os.makedirs(config_dir, exist_ok=True)

    # Write rnsd config
    config_path = os.path.join(config_dir, "config")
    if instance_type == "unix":
        content = (
            "[reticulum]\n"
            "  share_instance = Yes\n"
            "  enable_transport = Yes\n"
        )
    else:
        data_port = port or 37428
        ctrl_port = control_port or 37429
        content = (
            f"[reticulum]\n"
            f"  share_instance = Yes\n"
            f"  shared_instance_type = tcp\n"
            f"  shared_instance_port = {data_port}\n"
            f"  instance_control_port = {ctrl_port}\n"
            f"  enable_transport = Yes\n"
        )
    with open(config_path, "w") as f:
        f.write(content)

    cmd = [sys.executable, "-m", "RNS.Utilities.rnsd", "--config", config_dir]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # rnsd doesn't emit a ready marker — wait for the socket/port to become
    # available.
    import socket as _socket
    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            raise RuntimeError(
                f"rnsd exited early (rc={proc.returncode}): "
                f"{stderr.decode(errors='replace')[-500:]}"
            )
        try:
            if instance_type == "unix":
                # Check for abstract socket
                s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect("\0rns/default")
                s.close()
                return proc
            else:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("127.0.0.1", data_port))
                s.close()
                return proc
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            time.sleep(0.3)

    proc.kill()
    proc.wait()
    raise RuntimeError(f"rnsd did not become ready within {timeout_secs}s")


def daemon_is_alive(proc):
    """Check if a daemon process is still running."""
    return proc.poll() is None


def read_wire_message(s):
    """Read a 4-byte big-endian length-prefixed message from a socket."""
    import struct
    hdr = b""
    while len(hdr) < 4:
        chunk = s.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("EOF")
        hdr += chunk
    length = struct.unpack(">I", hdr)[0]
    data = b""
    while len(data) < length:
        chunk = s.recv(length - len(data))
        if not chunk:
            raise ConnectionError("EOF")
        data += chunk
    return data


def write_wire_message(s, payload):
    """Write a 4-byte big-endian length-prefixed message to a socket."""
    import struct
    s.sendall(struct.pack(">I", len(payload)) + payload)
