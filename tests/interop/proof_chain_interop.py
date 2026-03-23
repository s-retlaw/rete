#!/usr/bin/env python3
"""E2E: Proof chain -- proof routes back through Rust relay.

Topology: Python_A -> rnsd1 -> Rust(relay) -> rnsd2 -> Python_B(PROVE_ALL)

Python_A sends DATA to Python_B. Python_B auto-proves.
Proof should route back through the relay chain to Python_A.

Startup order matters for announce propagation:
  1. Python_A connects to rnsd1 (does NOT announce yet -- announcing can
     trigger rnsd rate-limiting that blocks later announces from arriving)
  2. Rust relay connects to both rnsd1 and rnsd2
  3. Python_B announces on rnsd2 -- Rust relay retransmits to rnsd1 --
     Python_A receives it
  4. Python_A sends data, Python_B auto-proves, proof routes back
"""

import time
from interop_helpers import InteropTest


def main():
    with InteropTest("proof-chain", default_port=4348, default_timeout=90) as t:
        rnsd_port1 = t.port
        rnsd_port2 = t.port + 1

        t.start_rnsd(port=rnsd_port1)
        t.start_rnsd(port=rnsd_port2)

        # Step 1: Start sender (Python_A) on rnsd1 FIRST.
        # It connects, waits for the "proofchain.receiver" path to appear,
        # then sends data and waits for proof.
        py_a = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_sender_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=rnsd_port1)}\"\"\")

reticulum = RNS.Reticulum(config_dir)
print("SENDER_READY", flush=True)

# Wait for a "proofchain.receiver" path to appear.
# We verify the destination hash matches the expected app/aspects
# to avoid accidentally using the Rust relay's announce.
deadline = time.time() + 45
receiver_dest_hash = None
while time.time() < deadline:
    for h in list(RNS.Transport.path_table.keys()):
        recalled = RNS.Identity.recall(h)
        if recalled is None:
            continue
        try:
            candidate = RNS.Destination(recalled, RNS.Destination.OUT,
                                         RNS.Destination.SINGLE,
                                         "proofchain", "receiver")
            if candidate.hash == h:
                receiver_dest_hash = h
                break
        except Exception:
            continue
    if receiver_dest_hash:
        break
    time.sleep(0.5)

if not receiver_dest_hash:
    table = list(RNS.Transport.path_table.keys())
    print(f"SENDER_NO_PATH:table_size={{len(table)}}", flush=True)
    for h in table:
        print(f"SENDER_PATH_ENTRY:{{h.hex()}}", flush=True)
    sys.exit(1)

print(f"SENDER_PATH_FOUND:{{receiver_dest_hash.hex()}}", flush=True)

try:
    receiver_identity = RNS.Identity.recall(receiver_dest_hash)
    if not receiver_identity:
        print("SENDER_RECALL_FAILED", flush=True)
        sys.exit(1)
    receiver_dest = RNS.Destination(receiver_identity, RNS.Destination.OUT,
                                     RNS.Destination.SINGLE, "proofchain", "receiver")

    # Send data and wait for proof
    proof_received = False

    def proof_callback(receipt):
        global proof_received
        proof_received = True
        print("SENDER_PROOF_RECEIVED", flush=True)

    packet = RNS.Packet(receiver_dest, b"proof-chain-test-data")
    receipt = packet.send()
    if receipt:
        receipt.set_delivery_callback(proof_callback)
    print("SENDER_DATA_SENT", flush=True)
except Exception as e:
    print(f"SENDER_ERROR:{{type(e).__name__}}:{{e}}", flush=True)
    sys.exit(1)

# Wait for proof
for _ in range(30):
    if proof_received:
        break
    time.sleep(1)

if not proof_received:
    print("SENDER_NO_PROOF", flush=True)

print("SENDER_DONE", flush=True)
""")

        sender_ready = t.wait_for_line(py_a, "SENDER_READY", timeout=15)
        t.check(sender_ready is not None, "Sender ready on rnsd1")

        # Wait for sender to fully establish TCP connection to rnsd1
        time.sleep(2)

        # Step 2: Start Rust relay connecting to both rnsd instances
        rust = t.start_rust(
            port=rnsd_port1,
            extra_args=["--connect", f"127.0.0.1:{rnsd_port2}", "--transport"],
        )

        time.sleep(3)

        # Step 3: Start receiver (Python_B) on rnsd2 with PROVE_ALL.
        # Its announce will propagate: rnsd2 -> Rust relay -> rnsd1 -> Python_A.
        py_b = t.start_py_helper(f"""\
import RNS, time, sys, os

config_dir = os.path.join("{t.tmpdir}", "py_receiver_config")
os.makedirs(config_dir, exist_ok=True)
with open(os.path.join(config_dir, "config"), "w") as cf:
    cf.write(\"\"\"{t.py_rns_config(port=rnsd_port2)}\"\"\")

reticulum = RNS.Reticulum(config_dir)

identity = RNS.Identity()
dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE,
                       "proofchain", "receiver")
dest.set_proof_strategy(RNS.Destination.PROVE_ALL)
dest.announce()
print(f"RECEIVER_HASH:{{dest.hexhash}}", flush=True)

def packet_callback(data, packet):
    print(f"RECEIVER_GOT_DATA:{{data.decode()}}", flush=True)

dest.set_packet_callback(packet_callback)

# Wait long enough for the full test
time.sleep(55)
print("RECEIVER_DONE", flush=True)
""")

        receiver_hash = t.wait_for_line(py_b, "RECEIVER_HASH")
        t.check(receiver_hash is not None, "Receiver announced on rnsd2")

        # Sender should discover receiver's announce via relay
        data_sent = t.wait_for_line(py_a, "SENDER_DATA_SENT", timeout=55)
        if data_sent is None:
            # Dump diagnostics
            t.dump_output("Sender output", py_a)
        t.check(data_sent is not None, "Sender found path and sent data")

        # Receiver should get the data
        got_data = t.wait_for_line(py_b, "RECEIVER_GOT_DATA", timeout=20)
        t.check(got_data is not None, "Receiver got data through relay")

        # Proof should route back
        proof = t.wait_for_line(py_a, "SENDER_PROOF_RECEIVED", timeout=20)
        t.check(proof is not None, "Proof routed back through relay chain")

        # Rust relay should still be alive
        t.check(t._rust_proc.poll() is None, "Rust relay survived proof chain")


if __name__ == "__main__":
    main()
