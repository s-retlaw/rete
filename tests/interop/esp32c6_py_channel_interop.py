#!/usr/bin/env python3
"""ESP32-C6 Python channel interop — Topology B (Python RNS <-> ESP32 via bridge).

Tests channel messaging over a link:
1. Python establishes link to ESP32
2. Python sends channel messages
3. ESP32 echoes back
4. Python verifies echoed content
"""

import os
import sys
import tempfile
import time

import RNS
import RNS.Channel

from interop_helpers import InteropTest


APP_NAME = "rete"
ASPECTS = ["example", "v1"]


class TestMessage(RNS.MessageBase):
    """Simple channel message for testing."""
    MSGTYPE = 0x0001

    def __init__(self, data=None):
        self.data = data or b""

    def pack(self):
        return self.data

    def unpack(self, raw):
        self.data = raw


BRIDGE_PORT = 4282


def main():
    with InteropTest("esp32c6-py-channel", default_port=0, default_timeout=30.0) as t:
        # Start serial bridge
        t.start_rust_serial_bridge(tcp_port=BRIDGE_PORT)

        # Create RNS instance
        tmpdir = tempfile.mkdtemp(prefix="rete_esp32c6_py_chan_")
        config_path = os.path.join(tmpdir, "config")
        with open(config_path, "w") as f:
            f.write(f"""\
[reticulum]
  enable_transport = no
  share_instance = no

[interfaces]
  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {BRIDGE_PORT}
""")

        rns = RNS.Reticulum(configdir=tmpdir, loglevel=RNS.LOG_VERBOSE)
        time.sleep(1.0)

        # Announce ourselves (also triggers ESP32 re-announce via idle-gap)
        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)
        our_dest.announce()

        # Wait for ESP32 announce — discover dynamically from path_table
        # since ESP32 generates a random identity on each boot.
        t._log("waiting for ESP32 announce (path discovery)...")
        esp32_dest_hash = None
        deadline = time.time() + t.timeout
        while time.time() < deadline:
            for h in RNS.Transport.path_table:
                if h != our_dest.hash:
                    esp32_dest_hash = h
                    break
            if esp32_dest_hash:
                break
            time.sleep(0.5)

        if esp32_dest_hash is None:
            t.check(False, "ESP32 path discovered via announce")
            RNS.Reticulum.exit_handler()
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
            return

        t._log(f"discovered ESP32 dest hash: {esp32_dest_hash.hex()}")
        esp32_id = RNS.Identity.recall(esp32_dest_hash)
        esp32_dest = RNS.Destination(
            esp32_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS
        )

        # Track events
        link_established = [False]
        received_messages = []

        def message_handler(message):
            received_messages.append(message.data)

        def link_established_cb(link):
            # Register channel handler immediately on establishment
            # so the ESP32 greeting (sent on link-up) isn't missed.
            channel = link.get_channel()
            channel.register_message_type(TestMessage)
            channel.add_message_handler(message_handler)
            link_established[0] = True

        # Initiate link
        t._log("initiating link to ESP32...")
        link = RNS.Link(esp32_dest)
        link.set_link_established_callback(link_established_cb)

        # Wait for link
        deadline = time.time() + 15
        while time.time() < deadline and not link_established[0]:
            time.sleep(0.3)

        t.check(link_established[0], "Link established with ESP32")

        if link_established[0]:
            # Wait for ESP32 greeting (arrives after LRRTT stabilization)
            deadline = time.time() + 8
            while time.time() < deadline:
                if any(b"esp32-hello" in m for m in received_messages):
                    break
                time.sleep(0.3)
            got_greeting = any(b"esp32-hello" in m for m in received_messages)
            t.check(got_greeting, "Received ESP32 greeting channel message",
                    detail=f"received {len(received_messages)} messages so far")

            # Send channel messages — space them out to allow channel window
            # proofs to round-trip over serial before the ESP32 window fills.
            t._log("sending channel messages...")
            channel = link.get_channel()
            msg1 = TestMessage(b"test-msg-one")
            channel.send(msg1)
            time.sleep(2)

            msg2 = TestMessage(b"test-msg-two")
            channel.send(msg2)

            # Wait for echoes
            deadline = time.time() + 10
            while time.time() < deadline:
                msgs = received_messages[:]
                if (any(b"echo:test-msg-one" in m for m in msgs) and
                        any(b"echo:test-msg-two" in m for m in msgs)):
                    break
                time.sleep(0.3)

            got_echo1 = any(b"echo:test-msg-one" in m for m in received_messages)
            got_echo2 = any(b"echo:test-msg-two" in m for m in received_messages)

            t.check(got_echo1, "Received echo of message 1")
            t.check(got_echo2, "Received echo of message 2")

            # Tear down
            link.teardown()
            time.sleep(1.0)

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
