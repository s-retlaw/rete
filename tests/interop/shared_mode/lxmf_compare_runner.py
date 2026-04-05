#!/usr/bin/env python3
"""Side-by-side LXMF comparison: Python rnsd vs rete-shared.

Long-lived clients where sender connects BEFORE receiver announces.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

RX_SCRIPT = r'''
import json, os, sys, time, threading
import RNS, LXMF
msgs = []; lock = threading.Lock()
def cb(m):
    with lock: msgs.append(m.content_as_string() if m.content else '')
    print(f"MSG_RECEIVED", flush=True)
rns = RNS.Reticulum(configdir=sys.argv[1])
print(f"RX_ATTACHED={rns.is_connected_to_shared_instance}", flush=True)
i = RNS.Identity()
st = os.path.join(sys.argv[1], 'ls'); os.makedirs(st, exist_ok=True)
r = LXMF.LXMRouter(identity=i, storagepath=st)
d = r.register_delivery_identity(i, display_name='Rx')
r.register_delivery_callback(cb)
time.sleep(5)  # Wait for sender to connect before announcing
d.announce()
print(f"RX_ANNOUNCED={d.hash.hex()}", flush=True)
with open(sys.argv[2], 'w') as f: json.dump({"dest_hash": d.hash.hex()}, f)
time.sleep(40)
with lock: json.dump({"count": len(msgs)}, open(sys.argv[3], 'w'))
try: rns.exit_handler()
except: pass
'''

TX_SCRIPT = r'''
import json, os, sys, time
import RNS, LXMF
rns = RNS.Reticulum(configdir=sys.argv[1])
print(f"TX_ATTACHED={rns.is_connected_to_shared_instance}", flush=True)
time.sleep(8)  # Wait for receiver to announce
target = bytes.fromhex(sys.argv[2])
tid = None
for i in range(200):
    tid = RNS.Identity.recall(target)
    if tid: break
    time.sleep(0.1)
hp = RNS.Transport.has_path(target)
print(f"TX_RECALL={tid is not None} TX_HASPATH={hp}", flush=True)
if not tid:
    json.dump({"sent": False, "error": "no_id"}, open(sys.argv[3], "w"))
    try: rns.exit_handler()
    except: pass
    sys.exit(0)
mi = RNS.Identity()
st = os.path.join(sys.argv[1], 'ls'); os.makedirs(st, exist_ok=True)
router = LXMF.LXMRouter(identity=mi, storagepath=st)
sd = router.register_delivery_identity(mi, display_name='Tx')
d = RNS.Destination(tid, RNS.Destination.OUT, RNS.Destination.SINGLE, 'lxmf', 'delivery')
lxm = LXMF.LXMessage(d, sd, 'Hello from wire compare!', title='WireTest')
lxm.desired_method = LXMF.LXMessage.DIRECT
router.handle_outbound(lxm)
for i in range(30):
    if lxm.state >= LXMF.LXMessage.SENT or lxm.state == LXMF.LXMessage.FAILED:
        print(f"TX_DONE state={lxm.state}", flush=True)
        break
    if i % 5 == 0:
        print(f"TX_STATE={lxm.state} at {i}s", flush=True)
    time.sleep(1)
json.dump({"state": lxm.state, "sent": lxm.state >= LXMF.LXMessage.SENT}, open(sys.argv[3], "w"))
try: rns.exit_handler()
except: pass
'''


def run_test(daemon_type, daemon_cmd, data_dir, tmpdir):
    print(f"\n{'='*60}")
    print(f"  {daemon_type}")
    print(f"{'='*60}")

    daemon = subprocess.Popen(daemon_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    daemon.stdout.readline()  # wait for ready
    time.sleep(2)
    print(f"  Daemon running: {daemon.poll() is None}")

    # Capture daemon stderr
    d_lines = []
    def read_err():
        while True:
            l = daemon.stderr.readline()
            if not l: break
            d_lines.append(l.decode(errors='replace').strip())
    threading.Thread(target=read_err, daemon=True).start()

    # Setup client dirs with shared transport_identity
    if daemon_type == "rete-shared":
        id_src = os.path.join(data_dir, "identity")
    else:
        id_src = os.path.join(data_dir, "storage", "transport_identity")

    for name in ["rx", "tx"]:
        d = os.path.join(tmpdir, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "config"), "w") as f:
            f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = No\n")
        if os.path.exists(id_src):
            st = os.path.join(d, "storage")
            os.makedirs(st, exist_ok=True)
            shutil.copy2(id_src, os.path.join(st, "transport_identity"))

    rx_dir = os.path.join(tmpdir, "rx")
    tx_dir = os.path.join(tmpdir, "tx")
    ready_file = os.path.join(tmpdir, "ready.json")
    rx_result = os.path.join(tmpdir, "rx_result.json")
    tx_result = os.path.join(tmpdir, "tx_result.json")

    # Start receiver
    rx = subprocess.Popen(
        [sys.executable, "-c", RX_SCRIPT, rx_dir, ready_file, rx_result],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Start sender IMMEDIATELY (before receiver announces)
    # Wait for ready file to get dest hash
    for _ in range(200):
        if os.path.exists(ready_file):
            with open(ready_file) as f:
                ready = json.load(f)
            break
        time.sleep(0.1)
    else:
        print("  ERROR: receiver never ready")
        daemon.kill(); rx.kill()
        return

    tx = subprocess.Popen(
        [sys.executable, "-c", TX_SCRIPT, tx_dir, ready["dest_hash"], tx_result],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Read stdout from both
    def print_output(proc, label):
        for line in proc.stdout:
            print(f"  [{label}] {line.decode().strip()}", flush=True)

    t1 = threading.Thread(target=print_output, args=(rx, "RX"), daemon=True)
    t2 = threading.Thread(target=print_output, args=(tx, "TX"), daemon=True)
    t1.start(); t2.start()

    tx.wait(timeout=50)
    rx.wait(timeout=55)
    time.sleep(1)

    # Results
    if os.path.exists(tx_result):
        print(f"  TX_RESULT: {json.load(open(tx_result))}")
    if os.path.exists(rx_result):
        print(f"  RX_RESULT: {json.load(open(rx_result))}")

    # Daemon logs
    if daemon_type == "rete-shared":
        frame_lines = [l for l in d_lines if 'frame' in l or 'relay' in l or 'LINK' in l]
        if frame_lines:
            print(f"  Daemon frames ({len(frame_lines)}):")
            for l in frame_lines:
                print(f"    {l}")

    daemon.send_signal(signal.SIGTERM)
    try: daemon.wait(timeout=5)
    except: daemon.kill()


def main():
    rust_binary = sys.argv[1] if len(sys.argv) > 1 else "/opt/rete/rete-shared"

    # Python rnsd
    py_tmp = tempfile.mkdtemp(prefix="cmp_py_")
    py_data = os.path.join(py_tmp, "daemon")
    os.makedirs(py_data, exist_ok=True)
    with open(os.path.join(py_data, "config"), "w") as f:
        f.write("[reticulum]\n  share_instance = Yes\n  enable_transport = Yes\n")

    run_test("python-rnsd",
        [sys.executable, "-c",
         f"import RNS,time;rns=RNS.Reticulum(configdir='{py_data}');print('RDY',flush=True);[time.sleep(1) for _ in iter(int,1)]"],
        py_data, py_tmp)

    time.sleep(2)

    # rete-shared
    rs_tmp = tempfile.mkdtemp(prefix="cmp_rs_")
    rs_data = os.path.join(rs_tmp, "daemon_data")
    os.makedirs(rs_data, exist_ok=True)

    run_test("rete-shared",
        [rust_binary, "--data-dir", rs_data, "--instance-name", "default",
         "--shared-instance-type", "unix", "--transport"],
        rs_data, rs_tmp)

    shutil.rmtree(py_tmp, ignore_errors=True)
    shutil.rmtree(rs_tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
