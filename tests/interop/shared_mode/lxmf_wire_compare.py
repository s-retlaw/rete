#!/usr/bin/env python3
"""Compare LXMF wire traffic through Python rnsd vs rete-shared.

Runs the same LXMF direct delivery test through both daemons with a
socket proxy logging every HDLC frame. Outputs two logs for diffing.

Usage (inside container):
    python3 lxmf_wire_compare.py --rust-binary /opt/rete/rete-shared
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from socket_proxy import SocketProxy


INSTANCE_NAME = "default"
DAEMON_SOCKET = f"\0rns/{INSTANCE_NAME}"
PROXY_SOCKET_PREFIX = "\0rns/proxy/"


def run_lxmf_test(daemon_type, daemon_cmd, data_dir, tmpdir, proxy_label):
    """Run LXMF delivery test with socket proxy. Returns (proxy_log, success)."""

    # Start daemon
    daemon = subprocess.Popen(
        daemon_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for daemon ready
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if daemon.poll() is not None:
            _, stderr = daemon.communicate()
            print(f"  [{daemon_type}] Daemon exited early: {stderr.decode()[-300:]}")
            return [], False
        try:
            import select
            ready = select.select([daemon.stdout], [], [], 0.2)
            if ready[0]:
                line = daemon.stdout.readline().decode().strip()
                if "READY" in line or "RDY" in line or "DAEMON_READY" in line:
                    break
        except:
            time.sleep(0.2)

    time.sleep(1)
    print(f"  [{daemon_type}] Daemon running: {daemon.poll() is None}")

    # Start proxy
    proxy_sock = f"{PROXY_SOCKET_PREFIX}{proxy_label}"
    proxy = SocketProxy(daemon_socket=DAEMON_SOCKET, proxy_socket=proxy_sock, label=daemon_type)
    proxy.start()

    # Client configs point to proxy socket (not daemon directly)
    def make_client_config(client_dir, instance_name=INSTANCE_NAME):
        os.makedirs(client_dir, exist_ok=True)
        # Override the socket path to go through our proxy
        with open(os.path.join(client_dir, "config"), "w") as f:
            f.write(f"[reticulum]\n  share_instance = Yes\n  enable_transport = No\n")

        # Copy transport_identity for RPC auth
        if daemon_type == "rete-shared":
            daemon_id = os.path.join(data_dir, "identity")
        else:
            daemon_id = os.path.join(data_dir, "storage", "transport_identity")

        if os.path.exists(daemon_id):
            client_storage = os.path.join(client_dir, "storage")
            os.makedirs(client_storage, exist_ok=True)
            shutil.copy2(daemon_id, os.path.join(client_storage, "transport_identity"))

    # Receiver
    rx_dir = os.path.join(tmpdir, "rx")
    make_client_config(rx_dir)
    ready_file = os.path.join(tmpdir, "rx_ready.json")
    result_rx = os.path.join(tmpdir, "rx_result.json")

    rx_script = os.path.join(tmpdir, "rx.py")
    with open(rx_script, "w") as f:
        f.write(textwrap.dedent(f"""\
            import json, os, sys, time, threading
            import RNS, LXMF
            msgs = []; lock = threading.Lock()
            def cb(m):
                with lock: msgs.append(m.content_as_string() if m.content else '')
            rns = RNS.Reticulum(configdir="{rx_dir}")
            i = RNS.Identity()
            st = os.path.join("{rx_dir}", "ls"); os.makedirs(st, exist_ok=True)
            r = LXMF.LXMRouter(identity=i, storagepath=st)
            d = r.register_delivery_identity(i, display_name="Rx")
            r.register_delivery_callback(cb)
            d.announce()
            with open("{ready_file}", "w") as f: json.dump({{"dest_hash": d.hash.hex()}}, f)
            time.sleep(45)
            with lock: json.dump({{"count": len(msgs), "msgs": msgs}}, open("{result_rx}", "w"))
            try: rns.exit_handler()
            except: pass
        """))

    rx_proc = subprocess.Popen([sys.executable, rx_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Wait for receiver ready
    for _ in range(150):
        if os.path.exists(ready_file):
            with open(ready_file) as f:
                ready = json.load(f)
            break
        time.sleep(0.1)
    else:
        print(f"  [{daemon_type}] Receiver never ready")
        proxy.stop()
        daemon.send_signal(signal.SIGTERM)
        return proxy.log_lines, False

    print(f"  [{daemon_type}] Receiver ready: {ready['dest_hash'][:16]}")
    time.sleep(3)

    # Sender
    tx_dir = os.path.join(tmpdir, "tx")
    make_client_config(tx_dir)
    result_tx = os.path.join(tmpdir, "tx_result.json")

    tx_script = os.path.join(tmpdir, "tx.py")
    with open(tx_script, "w") as f:
        f.write(textwrap.dedent(f"""\
            import json, os, sys, time
            import RNS, LXMF
            rns = RNS.Reticulum(configdir="{tx_dir}")
            time.sleep(5)
            target = bytes.fromhex("{ready['dest_hash']}")
            tid = None
            for _ in range(200):
                tid = RNS.Identity.recall(target)
                if tid: break
                time.sleep(0.1)
            if not tid:
                json.dump({{"sent": False, "error": "no_id"}}, open("{result_tx}", "w"))
                try: rns.exit_handler()
                except: pass
                sys.exit(0)
            mi = RNS.Identity()
            st = os.path.join("{tx_dir}", "ls"); os.makedirs(st, exist_ok=True)
            router = LXMF.LXMRouter(identity=mi, storagepath=st)
            sd = router.register_delivery_identity(mi, display_name="Tx")
            d = RNS.Destination(tid, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery")
            lxm = LXMF.LXMessage(d, sd, "Hello from wire compare!", title="WireTest")
            lxm.desired_method = LXMF.LXMessage.DIRECT
            router.handle_outbound(lxm)
            for i in range(30):
                if lxm.state >= LXMF.LXMessage.SENT or lxm.state == LXMF.LXMessage.FAILED: break
                time.sleep(1)
            json.dump({{"state": lxm.state, "sent": lxm.state >= LXMF.LXMessage.SENT}}, open("{result_tx}", "w"))
            try: rns.exit_handler()
            except: pass
        """))

    tx_proc = subprocess.Popen([sys.executable, tx_script], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tx_proc.wait(timeout=45)
    rx_proc.wait(timeout=50)

    time.sleep(2)
    proxy.stop()

    # Results
    tx_result = json.load(open(result_tx)) if os.path.exists(result_tx) else {"error": "no_result"}
    rx_result = json.load(open(result_rx)) if os.path.exists(result_rx) else {"error": "no_result"}
    print(f"  [{daemon_type}] Sender: {tx_result}")
    print(f"  [{daemon_type}] Receiver: {rx_result}")

    daemon.send_signal(signal.SIGTERM)
    try:
        daemon.wait(timeout=5)
    except:
        daemon.kill()

    return proxy.log_lines, rx_result.get("count", 0) > 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-binary", default="/opt/rete/rete-shared")
    args = parser.parse_args()

    print("=" * 60)
    print("LXMF Wire Traffic Comparison")
    print("=" * 60)

    # --- Python rnsd ---
    print("\n--- Python rnsd ---")
    py_tmpdir = tempfile.mkdtemp(prefix="lxmf_py_")
    py_data_dir = os.path.join(py_tmpdir, "daemon")
    os.makedirs(py_data_dir, exist_ok=True)
    with open(os.path.join(py_data_dir, "config"), "w") as f:
        f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = Yes\n")

    py_log, py_ok = run_lxmf_test(
        "python-rnsd",
        [sys.executable, "-c",
         f"import RNS,time;rns=RNS.Reticulum(configdir='{py_data_dir}');print('RDY',flush=True);[time.sleep(1) for _ in iter(int,1)]"],
        py_data_dir,
        py_tmpdir,
        "py",
    )

    # --- rete-shared ---
    print("\n--- rete-shared ---")
    rs_tmpdir = tempfile.mkdtemp(prefix="lxmf_rs_")
    rs_data_dir = os.path.join(rs_tmpdir, "daemon_data")
    os.makedirs(rs_data_dir, exist_ok=True)

    rs_log, rs_ok = run_lxmf_test(
        "rete-shared",
        [args.rust_binary, "--data-dir", rs_data_dir, "--instance-name", INSTANCE_NAME,
         "--shared-instance-type", "unix", "--transport"],
        rs_data_dir,
        rs_tmpdir,
        "rs",
    )

    # --- Compare ---
    print("\n" + "=" * 60)
    print("COMPARISON")
    print("=" * 60)
    print(f"Python rnsd: {len(py_log)} frames, delivery={'OK' if py_ok else 'FAIL'}")
    print(f"rete-shared: {len(rs_log)} frames, delivery={'OK' if rs_ok else 'FAIL'}")

    print("\n--- Python rnsd frames ---")
    for line in py_log:
        print(f"  {line}")

    print("\n--- rete-shared frames ---")
    for line in rs_log:
        print(f"  {line}")

    # Cleanup
    shutil.rmtree(py_tmpdir, ignore_errors=True)
    shutil.rmtree(rs_tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
