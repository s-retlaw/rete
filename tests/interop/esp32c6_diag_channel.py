#!/usr/bin/env python3
"""Diagnostic: ESP32-C6 channel test with full packet capture (Topology B).

Uses the diagnostic serial bridge to capture the full link handshake
and channel message flow in both directions, pinpointing where channel
messages stop.

Usage:
    cd tests/interop
    uv run python esp32c6_diag_channel.py --serial-port /dev/ttyUSB0 --timeout 30
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
BRIDGE_PORT = 4282


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
        return cls(raw)


def main():
    with InteropTest("esp32c6-diag-channel", default_port=0, default_timeout=30.0) as t:
        # Start DIAGNOSTIC serial bridge
        bridge = t.start_diag_serial_bridge(tcp_port=BRIDGE_PORT)

        # Create RNS instance
        tmpdir = tempfile.mkdtemp(prefix="rete_esp32c6_diag_chan_")
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

        # Setup ESP32 destination
        esp32_id = identity_from_seed(ESP32_SEED)
        esp32_dest_hash = RNS.Destination.hash_from_name_and_identity(
            f"{APP_NAME}.{'.'.join(ASPECTS)}", esp32_id
        )
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

        # Announce ourselves first to trigger ESP32 re-announce
        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)
        t._log("=== Sending Python announce (triggers ESP32 re-announce) ===")
        our_dest.announce()
        time.sleep(3.0)

        # Track events
        link_established = [False]
        link_established_time = [0.0]
        received_messages = []

        def message_handler(message):
            t._log(f"CHANNEL_MSG received: {message.data!r}")
            received_messages.append(message.data)

        def link_established_cb(link):
            channel = link.get_channel()
            channel.register_message_type(TestMessage)
            channel.add_message_handler(message_handler)
            link_established[0] = True
            link_established_time[0] = time.time()
            t._log("LINK ESTABLISHED")

        # Initiate link
        t._log("=== Initiating link to ESP32 ===")
        link = RNS.Link(esp32_dest)
        link.set_link_established_callback(link_established_cb)

        # Wait for link
        deadline = time.time() + 15
        while time.time() < deadline and not link_established[0]:
            time.sleep(0.3)

        t.check(link_established[0], "Link established with ESP32")

        if link_established[0]:
            # Wait for ESP32 greeting
            t._log("=== Waiting for ESP32 greeting ===")
            deadline = time.time() + 10
            while time.time() < deadline:
                if any(b"esp32-hello" in m for m in received_messages):
                    break
                time.sleep(0.3)
            got_greeting = any(b"esp32-hello" in m for m in received_messages)
            t.check(got_greeting, "Received ESP32 greeting channel message",
                    detail=f"received {len(received_messages)} messages so far: {received_messages!r}")

            # Send channel messages
            t._log("=== Sending channel messages ===")
            channel = link.get_channel()
            msg1 = TestMessage(b"test-msg-one")
            t._log(f"Sending: test-msg-one")
            channel.send(msg1)
            time.sleep(0.5)

            msg2 = TestMessage(b"test-msg-two")
            t._log(f"Sending: test-msg-two")
            channel.send(msg2)

            # Wait for echoes
            t._log("=== Waiting for echoes ===")
            deadline = time.time() + 10
            while time.time() < deadline:
                msgs = received_messages[:]
                if (any(b"echo:test-msg-one" in m for m in msgs) and
                        any(b"echo:test-msg-two" in m for m in msgs)):
                    break
                time.sleep(0.3)

            got_echo1 = any(b"echo:test-msg-one" in m for m in received_messages)
            got_echo2 = any(b"echo:test-msg-two" in m for m in received_messages)

            t.check(got_echo1, "Received echo of message 1",
                    detail=f"all messages: {received_messages!r}")
            t.check(got_echo2, "Received echo of message 2",
                    detail=f"all messages: {received_messages!r}")

            link.teardown()
            time.sleep(1.0)

        # Dump bridge stderr for packet-level diagnostics
        t._log("=== Diagnostic bridge packet log (stderr) ===")
        if bridge.stderr:
            try:
                import select as sel
                while True:
                    ready, _, _ = sel.select([bridge.stderr], [], [], 0.1)
                    if not ready:
                        break
                    data = bridge.stderr.read(4096)
                    if not data:
                        break
                    for line in data.decode(errors="replace").split("\n"):
                        if line.strip():
                            t._log(f"  [bridge] {line}")
            except Exception as e:
                t._log(f"  (could not read bridge stderr: {e})")

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()
