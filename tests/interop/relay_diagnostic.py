#!/usr/bin/env python3
"""Diagnostic test: trace exact packet flow through Rust transport relay.

Topology with TCP proxies:
  Python_A <-TCP:P1-> rnsd_1 <-TCP:P2-> PROXY_1 <-TCP:P3-> Rust <-TCP:P4-> PROXY_2 <-TCP:P5-> rnsd_2 <-TCP:P6-> Python_B

Proxies sit between Rust and each rnsd, logging every packet with timestamps.
This reveals:
  - Whether Rust sends H2 retransmissions (and when)
  - Whether rnsd accepts and retransmits them (and when)
  - The exact wire format of every packet
  - End-to-end latency at each hop

Usage:
  cd tests/interop
  uv run python relay_diagnostic.py --rust-binary ../../target/debug/rete-linux
"""

import os
import subprocess
import sys
import time

from interop_helpers import InteropTest, wait_for_port
from tcp_proxy import TcpProxy


def main():
    with InteropTest("relay-diag", default_port=4270) as t:
        port_rnsd1 = t.port         # 4270 — rnsd_1 listens here
        port_rnsd2 = t.port + 1     # 4271 — rnsd_2 listens here
        port_proxy1 = t.port + 2    # 4272 — proxy_1: Rust <-> rnsd_1
        port_proxy2 = t.port + 3    # 4273 — proxy_2: Rust <-> rnsd_2
        port_proxy3 = t.port + 4    # 4274 — proxy_3: Python_A <-> rnsd_1
        port_proxy4 = t.port + 5    # 4275 — proxy_4: Python_B <-> rnsd_2
        port_pyA = t.port + 4       # Python_A connects via proxy_3
        port_pyB = t.port + 5       # Python_B connects via proxy_4

        # --- Start rnsd instances ---
        t.start_rnsd(port=port_rnsd1)
        t.start_rnsd(port=port_rnsd2)

        # --- Start TCP proxies between Rust and rnsd ---
        print(f"\n[diag] Starting proxy_1: :{port_proxy1} -> :{port_rnsd1}", flush=True)
        proxy1 = TcpProxy(
            listen_port=port_proxy1,
            target_host="127.0.0.1",
            target_port=port_rnsd1,
            label="PROXY1(Rust<->rnsd1)",
        )
        proxy1.start()

        print(f"[diag] Starting proxy_2: :{port_proxy2} -> :{port_rnsd2}", flush=True)
        proxy2 = TcpProxy(
            listen_port=port_proxy2,
            target_host="127.0.0.1",
            target_port=port_rnsd2,
            label="PROXY2(Rust<->rnsd2)",
        )
        proxy2.start()

        # --- Proxies for Python nodes <-> rnsd ---
        print(f"[diag] Starting proxy_3: :{port_proxy3} -> :{port_rnsd1} (Python_A <-> rnsd_1)", flush=True)
        proxy3 = TcpProxy(
            listen_port=port_proxy3,
            target_host="127.0.0.1",
            target_port=port_rnsd1,
            label="PROXY3(PyA<->rnsd1)",
        )
        proxy3.start()

        print(f"[diag] Starting proxy_4: :{port_proxy4} -> :{port_rnsd2} (Python_B <-> rnsd_2)", flush=True)
        proxy4 = TcpProxy(
            listen_port=port_proxy4,
            target_host="127.0.0.1",
            target_port=port_rnsd2,
            label="PROXY4(PyB<->rnsd2)",
        )
        proxy4.start()

        # Wait for proxies to bind
        assert wait_for_port("127.0.0.1", port_proxy1, timeout=5), "proxy1 failed to start"
        assert wait_for_port("127.0.0.1", port_proxy2, timeout=5), "proxy2 failed to start"
        assert wait_for_port("127.0.0.1", port_proxy3, timeout=5), "proxy3 failed to start"
        assert wait_for_port("127.0.0.1", port_proxy4, timeout=5), "proxy4 failed to start"

        # --- Start Rust transport node (connects via proxies) ---
        rust = t.start_rust(
            port=port_proxy1,  # connects to proxy_1 (which forwards to rnsd_1)
            extra_args=[
                "--connect", f"127.0.0.1:{port_proxy2}",  # connects to proxy_2 (which forwards to rnsd_2)
                "--transport",
            ],
        )

        rust_dest_hex = t.wait_for_line(rust, "IDENTITY:", timeout=10) or ""
        print(f"\n[diag] Rust identity: {rust_dest_hex}", flush=True)
        time.sleep(3)

        # --- Start Python_A (connects directly to rnsd_1) ---
        print("\n[diag] Starting Python_A (connects to rnsd_1)...", flush=True)
        py_a = t.start_py_helper(f"""\
import RNS
import time
import os

config_dir = os.path.join("{t.tmpdir}", "py_a_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port_pyA, transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
print(f"PY_A_DEST:{{dest.hexhash}}", flush=True)
print("PY_A_CONNECTED", flush=True)

# Wait for Python_B to connect before announcing
time.sleep(3)

dest.announce()
print(f"PY_A_ANNOUNCED:{{time.time():.3f}}", flush=True)

# Poll for peer announce
deadline = time.time() + 30
peer_hash = None
while time.time() < deadline:
    for h in RNS.Transport.path_table:
        if h == dest.hash:
            continue
        if exclude_hash and h == exclude_hash:
            continue
        peer_hash = h
        break
    if peer_hash:
        break
    time.sleep(0.2)

if peer_hash:
    print(f"PY_A_DISCOVERED:{{peer_hash.hex()}}:{{time.time():.3f}}", flush=True)
    peer_identity = RNS.Identity.recall(peer_hash)
    if peer_identity:
        out_dest = RNS.Destination(
            peer_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
            "rete", "example", "v1",
        )
        packet = RNS.Packet(out_dest, b"diag-ping")
        receipt = packet.send()
        print(f"PY_A_SENT_DATA:{{time.time():.3f}}", flush=True)
    else:
        print("PY_A_IDENTITY_NOT_RECALLED", flush=True)
else:
    print("PY_A_PEER_NOT_FOUND", flush=True)

time.sleep(5)
print("PY_A_DONE", flush=True)
""")

        # Wait for Python_A to be ready
        t.wait_for_line(py_a, "PY_A_CONNECTED", timeout=10)
        time.sleep(1)

        # --- Start Python_B (connects directly to rnsd_2) ---
        print("\n[diag] Starting Python_B (connects to rnsd_2)...", flush=True)
        py_b = t.start_py_helper(f"""\
import RNS
import time
import os
import threading

config_dir = os.path.join("{t.tmpdir}", "py_b_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=port_pyB, transport=False)}\"\"\")

reticulum = RNS.Reticulum(configdir=config_dir)

exclude_hex = "{rust_dest_hex}"
exclude_hash = bytes.fromhex(exclude_hex) if exclude_hex else None

data_received = threading.Event()

def packet_callback(data, packet):
    text = data.decode("utf-8", errors="replace")
    print(f"PY_B_DATA_RECEIVED:{{text}}:{{time.time():.3f}}", flush=True)
    data_received.set()

identity = RNS.Identity()
dest = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE,
    "rete", "example", "v1",
)
dest.set_packet_callback(packet_callback)
print(f"PY_B_DEST:{{dest.hexhash}}", flush=True)
print("PY_B_CONNECTED", flush=True)

# Wait a moment then announce
time.sleep(1)
dest.announce()
print(f"PY_B_ANNOUNCED:{{time.time():.3f}}", flush=True)

# Poll for peer announce
deadline = time.time() + 30
peer_hash = None
while time.time() < deadline:
    for h in RNS.Transport.path_table:
        if h == dest.hash:
            continue
        if exclude_hash and h == exclude_hash:
            continue
        peer_hash = h
        break
    if peer_hash:
        break
    time.sleep(0.2)

if peer_hash:
    print(f"PY_B_DISCOVERED:{{peer_hash.hex()}}:{{time.time():.3f}}", flush=True)
else:
    print("PY_B_PEER_NOT_FOUND", flush=True)

# Wait for data
if data_received.wait(timeout=15):
    print("PY_B_DATA_OK", flush=True)
else:
    print("PY_B_DATA_TIMEOUT", flush=True)

time.sleep(2)
print("PY_B_DONE", flush=True)
""")

        # Wait for both to finish
        t.wait_for_line(py_a, "PY_A_DONE", timeout=60)
        t.wait_for_line(py_b, "PY_B_DONE", timeout=60)

        time.sleep(1)

        # --- Collect and display results ---
        print("\n" + "=" * 80, flush=True)
        print("  PACKET TRACE SUMMARY", flush=True)
        print("=" * 80, flush=True)

        print("\n--- PROXY 1 (Rust <-> rnsd_1) ---", flush=True)
        log1 = proxy1.get_log()
        if not log1:
            print("  (no packets captured)", flush=True)
        for _, _, _, formatted in log1:
            print(f"  {formatted}", flush=True)

        print(f"\n--- PROXY 2 (Rust <-> rnsd_2) ---", flush=True)
        log2 = proxy2.get_log()
        if not log2:
            print("  (no packets captured)", flush=True)
        for _, _, _, formatted in log2:
            print(f"  {formatted}", flush=True)

        print(f"\n--- PROXY 3 (Python_A <-> rnsd_1) ---", flush=True)
        log3 = proxy3.get_log()
        if not log3:
            print("  (no packets captured)", flush=True)
        for _, _, _, formatted in log3:
            print(f"  {formatted}", flush=True)

        print(f"\n--- PROXY 4 (Python_B <-> rnsd_2) ---", flush=True)
        log4 = proxy4.get_log()
        if not log4:
            print("  (no packets captured)", flush=True)
        for _, _, _, formatted in log4:
            print(f"  {formatted}", flush=True)

        # --- Analysis ---
        print("\n" + "=" * 80, flush=True)
        print("  ANALYSIS", flush=True)
        print("=" * 80, flush=True)

        all_log = [(e, d, i, f, "P1") for e, d, i, f in log1] + \
                  [(e, d, i, f, "P2") for e, d, i, f in log2] + \
                  [(e, d, i, f, "P3") for e, d, i, f in log3] + \
                  [(e, d, i, f, "P4") for e, d, i, f in log4]
        all_log.sort(key=lambda x: x[0])

        # Count by type
        announces_from_rust = 0
        announces_to_rust = 0
        data_from_rust = 0
        data_to_rust = 0
        for elapsed, direction, info, _, proxy_label in all_log:
            pkt_type = info.get("pkt_type", "?")
            if direction == ">>>":  # Rust -> rnsd
                if pkt_type == "ANNOUNCE":
                    announces_from_rust += 1
                elif pkt_type == "DATA":
                    data_from_rust += 1
            else:  # rnsd -> Rust
                if pkt_type == "ANNOUNCE":
                    announces_to_rust += 1
                elif pkt_type == "DATA":
                    data_to_rust += 1

        print(f"\n  Announces: Rust->rnsd: {announces_from_rust}, rnsd->Rust: {announces_to_rust}")
        print(f"  Data:      Rust->rnsd: {data_from_rust}, rnsd->Rust: {data_to_rust}")

        # Find announce propagation times
        print("\n  Announce flow (chronological):")
        for elapsed, direction, info, _, proxy_label in all_log:
            if info.get("pkt_type") == "ANNOUNCE":
                dest = info.get("dest_hash", "?")[:16]
                hdr = info.get("header", "?")
                hops = info.get("hops", "?")
                tid = info.get("transport_id", "")[:16]
                tid_str = f" tid={tid}" if tid else ""
                print(f"    {elapsed:8.1f}ms {proxy_label} {direction} {hdr} ANNOUNCE dest={dest} hops={hops}{tid_str}")

        # Dump Python output
        print("\n--- Python_A output ---", flush=True)
        t.dump_output("Python_A", py_a)
        print("\n--- Python_B output ---", flush=True)
        t.dump_output("Python_B", py_b)

        # Dump Rust stderr (last 30 lines)
        rust_stderr = t.collect_rust_stderr()
        print("\n--- Rust stderr (last 30 lines) ---", flush=True)
        for line in rust_stderr.strip().split("\n")[-30:]:
            print(f"  {line}", flush=True)

        # --- Pass/Fail ---
        py_a_found = t.has_line(py_a, "PY_A_DISCOVERED:")
        py_b_found = t.has_line(py_b, "PY_B_DISCOVERED:")
        py_b_data = t.has_line(py_b, "PY_B_DATA_RECEIVED:")

        print("\n" + "=" * 80, flush=True)
        t.check(py_a_found, "Python_A discovered Python_B via Rust relay")
        t.check(py_b_found, "Python_B discovered Python_A via Rust relay")
        t.check(py_b_data, "Python_B received DATA from Python_A via Rust relay")

        proxy1.stop()
        proxy2.stop()
        proxy3.stop()
        proxy4.stop()


if __name__ == "__main__":
    main()
