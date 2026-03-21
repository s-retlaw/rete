#!/usr/bin/env python3
"""ESP32-C6 3-node relay interop — Topology C (Python RNS <-> rete-linux relay <-> ESP32).

Tests multi-hop relay through the Rust node:

  Python RNS <-TCP-> rnsd (transport) <-TCP-> rete-linux (--transport) <-serial-> ESP32

Phases:
  1. Announce propagation (ESP32 -> Python through relay)
  2. Encrypted DATA round-trip + proof of delivery
  3. Link through relay (Python -> ESP32)
  4. Channel message through relay
  5. Request/response through relay
  6. Resource transfer through relay
  7. Teardown (link close)
  8. Fill all 4 link slots through relay + slot reuse
  9. ESP32-initiated link through relay
 10. Final crash check

Usage:
  cd tests/interop
  uv run python esp32c6_3node_relay_interop.py \
      --rust-binary ../../target/debug/rete-linux \
      --serial-port /dev/ttyUSB0 --timeout 120
"""

import hashlib
import os
import sys
import tempfile
import time

import RNS
import RNS.Channel

from interop_helpers import InteropTest


ESP32_SEED = "rete-esp32c6-test"
APP_NAME = "rete"
ASPECTS = ["example", "v1"]
RNSD_PORT = 4290


def identity_from_seed(seed_str):
    h1 = hashlib.sha256(seed_str.encode()).digest()
    h2 = hashlib.sha256(h1).digest()
    prv = h1 + h2
    id_ = RNS.Identity(create_keys=False)
    id_.load_private_key(prv)
    return id_


class TestMessage(RNS.MessageBase):
    """Simple channel message for testing."""
    MSGTYPE = 0x0001

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data

    @classmethod
    def unpack(cls, raw):
        msg = cls(raw)
        return msg


def main():
    with InteropTest("esp32c6-3node-relay", default_port=RNSD_PORT, default_timeout=180.0) as t:
        # --- Setup topology ---
        # 1. Start rnsd (transport relay)
        t.start_rnsd(port=RNSD_PORT)

        # 2. Start Python RNS FIRST so it's connected to rnsd before rete-linux
        #    sends the synthetic peer announce (which rnsd will forward to Python).
        py_tmpdir = tempfile.mkdtemp(prefix="rete_3node_py_")
        py_config_path = os.path.join(py_tmpdir, "config")
        with open(py_config_path, "w") as f:
            f.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[interfaces]
  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {RNSD_PORT}
""")

        rns = RNS.Reticulum(configdir=py_tmpdir, loglevel=RNS.LOG_VERBOSE)
        time.sleep(1.0)

        # 3. Start rete-linux with TCP + serial (multi-interface, transport mode).
        #    --peer-seed pre-registers ESP32 identity + builds cached announce
        #    that gets flushed to TCP interface on startup (toward rnsd/Python).
        rust_lines = t.start_rust_dual(
            seed="3node-relay-42",
            port=RNSD_PORT,
            extra_args=["--transport", "--peer-seed", ESP32_SEED],
        )

        # 4. Wait for rete-linux to connect and cached announce to propagate
        time.sleep(5.0)
        t._log("rete-linux started, peer announce cached and flushed")

        # Create ESP32 identity from seed (for destination hash computation)
        esp32_id = identity_from_seed(ESP32_SEED)
        esp32_dest_hash = RNS.Destination.hash_from_name_and_identity(
            f"{APP_NAME}.{'.'.join(ASPECTS)}", esp32_id
        )

        # Register ESP32's identity so we can reach it
        RNS.Identity.remember(
            packet_hash=None,
            destination_hash=esp32_dest_hash,
            public_key=esp32_id.get_public_key(),
            app_data=None,
        )

        esp32_dest = RNS.Destination(
            esp32_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS
        )

        # Create our own identity and destination
        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)

        # Track received packets
        received_packets = []

        def packet_callback(data, packet):
            received_packets.append(data)

        our_dest.set_packet_callback(packet_callback)

        # === Phase 1: Announce propagation ===
        t._log("=== Phase 1: Announce propagation ===")

        # Wait for ESP32 announce to reach Python through rnsd + rete-linux relay
        # The rete-linux transport node should have retransmitted the ESP32 announce
        deadline = time.time() + 20
        esp32_path_found = False
        while time.time() < deadline:
            if RNS.Transport.has_path(esp32_dest_hash):
                esp32_path_found = True
                break
            time.sleep(0.5)

        t.check(esp32_path_found, "Python received ESP32 announce through relay")

        # Check hops (announce went: ESP32 -> serial -> rete-linux -> TCP -> rnsd -> TCP -> Python)
        hops = RNS.Transport.hops_to(esp32_dest_hash)
        t.check(hops >= 1, f"Announce hops >= 1 (got {hops})")

        if not esp32_path_found:
            t._log("Cannot proceed without path to ESP32")
            # Collect diagnostics
            rust_stderr = t.collect_rust_stderr()
            t.dump_output("Rust stdout", rust_lines)
            t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))
            RNS.Reticulum.exit_handler()
            import shutil
            shutil.rmtree(py_tmpdir, ignore_errors=True)
            return

        # === Phase 2: Encrypted DATA round-trip ===
        t._log("=== Phase 2: Encrypted DATA round-trip ===")

        # Announce ourselves so ESP32 can learn our identity for echo
        our_dest.announce()
        time.sleep(3.0)

        # Send encrypted DATA to ESP32
        ts = int(time.time())
        ping_msg = f"ping:{ts}".encode()
        t._log(f"sending encrypted DATA: ping:{ts}")
        pkt = RNS.Packet(esp32_dest, ping_msg)

        # Set up proof callback
        proof_received = [False]

        def delivery_callback(receipt):
            proof_received[0] = True

        pkt.send()
        receipt = pkt.receipt
        if receipt:
            receipt.set_delivery_callback(delivery_callback)

        # Wait for echo
        deadline = time.time() + 15
        while time.time() < deadline and len(received_packets) == 0:
            time.sleep(0.3)

        got_echo = len(received_packets) > 0
        if got_echo:
            echo_data = received_packets[0]
            expected = f"echo:ping:{ts}".encode()
            t.check(echo_data == expected, "DATA echo matches expected payload",
                    detail=f"expected={expected!r}, got={echo_data!r}")
        else:
            t.check(False, "Received echo DATA from ESP32 through relay",
                    detail="no packets received")

        # Wait for proof (ESP32 has ProveAll, proof routes back through relay)
        if not proof_received[0]:
            deadline = time.time() + 10
            while time.time() < deadline and not proof_received[0]:
                time.sleep(0.3)

        t.check(proof_received[0], "Proof of delivery received through relay")

        # === Phase 3: Link through relay ===
        t._log("=== Phase 3: Link through relay ===")

        link_established = [False]
        link_closed = [False]
        received_link_data = []

        def link_established_cb(link):
            link_established[0] = True

        def link_closed_cb(link):
            link_closed[0] = True

        def link_packet_callback(message, packet):
            received_link_data.append(message)

        link = RNS.Link(esp32_dest)
        link.set_link_established_callback(link_established_cb)
        link.set_link_closed_callback(link_closed_cb)
        link.set_packet_callback(link_packet_callback)

        # Wait for link establishment
        deadline = time.time() + 20
        while time.time() < deadline and not link_established[0]:
            time.sleep(0.3)

        t.check(link_established[0], "Link established through relay")

        if not link_established[0]:
            t._log("Cannot proceed without link")
            rust_stderr = t.collect_rust_stderr()
            t.dump_output("Rust stdout", rust_lines)
            t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))
            RNS.Reticulum.exit_handler()
            import shutil
            shutil.rmtree(py_tmpdir, ignore_errors=True)
            return

        # === Phase 4: Channel message through relay ===
        t._log("=== Phase 4: Channel messages ===")

        # Register channel handler BEFORE LRRTT stabilization so the ESP32
        # greeting (sent once link is established) is captured during the wait.
        received_channel_msgs = []

        def channel_msg_handler(message):
            received_channel_msgs.append(message.data)

        channel = link.get_channel()
        channel.register_message_type(TestMessage)
        channel.add_message_handler(channel_msg_handler)

        time.sleep(2.0)  # LRRTT stabilization — greeting may arrive here

        # Wait for ESP32 greeting
        time.sleep(3.0)
        got_greeting = any(b"esp32-hello" in m for m in received_channel_msgs)
        t.check(got_greeting, "ESP32 greeting received through relay",
                detail=f"received {len(received_channel_msgs)} channel msgs")

        # Send channel message and verify echo
        msg = TestMessage(b"relay-test-msg")
        channel.send(msg)

        deadline = time.time() + 10
        while time.time() < deadline:
            if any(b"echo:relay-test-msg" in m for m in received_channel_msgs):
                break
            time.sleep(0.3)

        got_channel_echo = any(b"echo:relay-test-msg" in m for m in received_channel_msgs)
        t.check(got_channel_echo, "Channel echo received through relay",
                detail=f"received {len(received_channel_msgs)} channel msgs total")

        # === Phase 5: Request/response through relay ===
        t._log("=== Phase 5: Request/response ===")

        request_response = [None]

        def response_callback(request_receipt):
            if request_receipt.response is not None:
                request_response[0] = request_receipt.response

        def request_failed(request_receipt):
            t._log(f"request failed: {request_receipt.status}")

        def request_progress(request_receipt):
            pass

        link.request(
            "/test",
            data=b"hello-from-python",
            response_callback=response_callback,
            failed_callback=request_failed,
            progress_callback=request_progress,
        )

        deadline = time.time() + 10
        while time.time() < deadline and request_response[0] is None:
            time.sleep(0.3)

        t.check(request_response[0] is not None, "Request response received through relay",
                detail=f"response={request_response[0]!r}")

        # === Phase 6: Resource transfer through relay ===
        t._log("=== Phase 6: Resource transfer ===")

        resource_complete = [False]

        def resource_concluded(resource):
            if resource.status == RNS.Resource.COMPLETE:
                resource_complete[0] = True

        # Send a small resource
        test_data = b"3node-relay-resource-test-payload-" + (b"X" * 100)
        resource = RNS.Resource(test_data, link, callback=resource_concluded)

        deadline = time.time() + 45
        while time.time() < deadline and not resource_complete[0]:
            time.sleep(0.3)

        t.check(resource_complete[0], "Resource transfer completed through relay")

        # === Phase 7: Teardown ===
        t._log("=== Phase 7: Teardown ===")

        link.teardown()
        time.sleep(5.0)
        t.check(link_closed[0] or link.status == RNS.Link.CLOSED,
                "Link closed cleanly")

        # === Phase 8: Fill all 4 link slots through relay ===
        t._log("=== Phase 8: 4 concurrent links ===")

        # We tore down the link in Phase 7, so all 4 ESP32 slots are free.
        # Establish 4 concurrent links, verify each with a channel message.
        links = []
        channels = []

        for i in range(4):
            ev = [False]
            lnk = RNS.Link(esp32_dest)
            lnk.set_link_established_callback(lambda l, e=ev: e.__setitem__(0, True))
            # Wait for establishment (30s per link, serial relay adds latency)
            deadline = time.time() + 30
            while time.time() < deadline and not ev[0]:
                time.sleep(0.3)
            if not ev[0]:
                t._log(f"link slot {i} failed to establish")
                break
            time.sleep(1.5)  # LRRTT stabilization
            links.append(lnk)

            # Set up channel on this link
            ch = lnk.get_channel()
            ch.register_message_type(TestMessage)
            msgs_i = []
            ch.add_message_handler(lambda m, acc=msgs_i: acc.append(m.data))
            channels.append((ch, msgs_i))

        t.check(len(links) == 4, f"All 4 link slots filled through relay (got {len(links)})")

        # Send a unique channel message on each link, verify echo
        for i, (ch, msgs) in enumerate(channels):
            tag = f"slot{i}-msg"
            ch.send(TestMessage(tag.encode()))

        time.sleep(5.0)  # wait for all echoes

        echoed = sum(1 for i, (_, msgs) in enumerate(channels)
                     if any(f"echo:slot{i}-msg".encode() in m for m in msgs))
        t.check(echoed == 4, f"Channel echo on all 4 links ({echoed}/4)")

        # Tear down all 4
        for lnk in links:
            lnk.teardown()
        time.sleep(8.0)  # 4 concurrent teardowns through relay need more time

        # Establish a 5th link — proves slot reuse after bulk teardown
        reuse_ev = [False]
        link5 = RNS.Link(esp32_dest)
        link5.set_link_established_callback(lambda l: reuse_ev.__setitem__(0, True))
        deadline = time.time() + 30
        while time.time() < deadline and not reuse_ev[0]:
            time.sleep(0.3)

        t.check(reuse_ev[0], "Link slot reuse after filling all 4 slots")

        if reuse_ev[0]:
            link5.teardown()
            time.sleep(2.0)

        # === Phase 9: ESP32-initiated link through relay ===
        t._log("=== Phase 9: ESP32-initiated link ===")

        # Set up inbound link callback on our destination
        inbound_link = [None]
        inbound_link_established = [False]

        def inbound_link_cb(link):
            inbound_link[0] = link
            inbound_link_established[0] = True

        our_dest.set_link_established_callback(inbound_link_cb)

        # Announce with "LINK_ME" app_data — triggers ESP32 to initiate link
        our_dest.announce(app_data=b"LINK_ME")

        # Wait for ESP32 to see announce and initiate link back
        deadline = time.time() + 30
        while time.time() < deadline and not inbound_link_established[0]:
            time.sleep(0.3)

        t.check(inbound_link_established[0], "ESP32-initiated link established through relay")

        if inbound_link_established[0] and inbound_link[0]:
            # Set up channel handler on the inbound link
            inbound_channel_msgs = []

            def inbound_channel_handler(message):
                inbound_channel_msgs.append(message.data)

            inbound_ch = inbound_link[0].get_channel()
            inbound_ch.register_message_type(TestMessage)
            inbound_ch.add_message_handler(inbound_channel_handler)

            # Wait for ESP32 greeting through channel
            time.sleep(2.0)  # LRRTT stabilization
            deadline = time.time() + 10
            while time.time() < deadline:
                if any(b"esp32-hello" in m for m in inbound_channel_msgs):
                    break
                time.sleep(0.3)

            got_inbound_greeting = any(b"esp32-hello" in m for m in inbound_channel_msgs)
            t.check(got_inbound_greeting, "ESP32 greeting on ESP32-initiated link",
                    detail=f"received {len(inbound_channel_msgs)} channel msgs")

            # Send channel message and verify echo
            inbound_ch.send(TestMessage(b"inbound-link-test"))
            deadline = time.time() + 10
            while time.time() < deadline:
                if any(b"echo:inbound-link-test" in m for m in inbound_channel_msgs):
                    break
                time.sleep(0.3)

            got_inbound_echo = any(b"echo:inbound-link-test" in m for m in inbound_channel_msgs)
            t.check(got_inbound_echo, "Channel echo on ESP32-initiated link",
                    detail=f"received {len(inbound_channel_msgs)} channel msgs total")

            # Teardown
            inbound_link[0].teardown()
            time.sleep(3.0)

        # === Phase 10: Final crash check ===
        t._log("=== Phase 10: Crash check ===")

        rust_stderr = t.collect_rust_stderr()
        has_panic = "panic" in rust_stderr.lower() or "SIGSEGV" in rust_stderr
        t.check(not has_panic, "No crash in rete-linux stderr",
                detail=rust_stderr[-200:] if has_panic else None)

        # Dump diagnostics
        t.dump_output("Rust stdout", rust_lines)
        t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(py_tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
