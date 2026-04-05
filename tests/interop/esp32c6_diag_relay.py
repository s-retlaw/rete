#!/usr/bin/env python3
"""Diagnostic: ESP32-C6 3-node relay with full packet capture (Topology C).

Uses the diagnostic serial bridge on the serial side and rns_proxy.py
on the TCP side to capture every HDLC frame in both segments:

  Python RNS <-TCP-> rnsd <-TCP:proxy-> rete <-serial:diag_bridge-> ESP32

Shows exactly where LINKREQUEST or LRPROOF is lost in the relay chain.

Usage:
    cd tests/interop
    uv run python esp32c6_diag_relay.py \
        --rust-binary ../../target/debug/rete \
        --serial-port /dev/ttyUSB0 --timeout 120
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
RNSD_PORT = 4290
PROXY_PORT = 4292  # proxy sits between rete and rnsd
BRIDGE_PORT = 4294  # diag bridge for serial side


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
    with InteropTest("esp32c6-diag-relay", default_port=RNSD_PORT, default_timeout=120.0) as t:
        # --- Setup topology with full instrumentation ---

        # 1. Start rnsd (transport relay)
        t.start_rnsd(port=RNSD_PORT)

        # 2. Start Python RNS FIRST
        py_tmpdir = tempfile.mkdtemp(prefix="rete_diag_relay_py_")
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
    ingress_control = false
""")

        rns = RNS.Reticulum(configdir=py_tmpdir, loglevel=RNS.LOG_VERBOSE)
        time.sleep(1.0)

        # 3. Start diagnostic serial bridge (serial side capture)
        t._log("=== Starting diagnostic serial bridge ===")
        bridge = t.start_diag_serial_bridge(tcp_port=BRIDGE_PORT)

        # 4. Start TCP proxy between rete and rnsd (TCP side capture)
        t._log("=== Starting TCP proxy (rete -> rnsd) ===")
        proxy = t.start_tcp_proxy(listen_port=PROXY_PORT, target_port=RNSD_PORT)

        # 5. Start rete connecting through proxy + serial bridge
        #    It connects to the proxy (which forwards to rnsd) on TCP side,
        #    and to the diag bridge (which forwards to ESP32) on serial side.
        rust_lines = t.start_rust(
            port=PROXY_PORT,
            extra_args=[
                "--transport",
                "--serial", f"127.0.0.1:{BRIDGE_PORT}",  # connect to diag bridge as TCP
            ],
        )

        # Wait for connections to establish
        time.sleep(5.0)
        t._log("=== Topology established ===")

        our_id = RNS.Identity()
        our_dest = RNS.Destination(our_id, RNS.Destination.IN, RNS.Destination.SINGLE,
                                    APP_NAME, *ASPECTS)

        # === Phase 1: Announce propagation ===
        t._log("=== Phase 1: Announce propagation ===")

        # Discover ESP32 dynamically from path_table since ESP32 generates
        # a random identity on each boot.
        esp32_dest_hash = None
        deadline = time.time() + 20
        while time.time() < deadline:
            for h in RNS.Transport.path_table:
                if h != our_dest.hash:
                    esp32_dest_hash = h
                    break
            if esp32_dest_hash:
                break
            time.sleep(0.5)

        esp32_path_found = esp32_dest_hash is not None
        t.check(esp32_path_found, "Python received ESP32 announce through relay")

        if not esp32_path_found:
            t._log("Cannot proceed without path to ESP32")
            rust_stderr = t.collect_rust_stderr()
            t.dump_output("Rust stdout", rust_lines)
            t.dump_output("Rust stderr (last 1000)", rust_stderr.strip().split("\n"))
            dump_bridge_stderr(t, bridge)
            dump_proxy_stderr(t, proxy)
            RNS.Reticulum.exit_handler()
            import shutil
            shutil.rmtree(py_tmpdir, ignore_errors=True)
            return

        t._log(f"discovered ESP32 dest hash: {esp32_dest_hash.hex()}")
        esp32_id = RNS.Identity.recall(esp32_dest_hash)
        esp32_dest = RNS.Destination(
            esp32_id, RNS.Destination.OUT, RNS.Destination.SINGLE,
            APP_NAME, *ASPECTS
        )

        # === Phase 2: DATA echo ===
        t._log("=== Phase 2: DATA echo ===")

        our_dest.announce()
        time.sleep(3.0)

        received_packets = []

        def packet_callback(data, packet):
            t._log(f"DATA received: {data!r}")
            received_packets.append(data)

        our_dest.set_packet_callback(packet_callback)

        ts = int(time.time())
        t._log(f"Sending encrypted DATA: ping:{ts}")
        pkt = RNS.Packet(esp32_dest, f"ping:{ts}".encode())
        pkt.send()

        deadline = time.time() + 15
        while time.time() < deadline and len(received_packets) == 0:
            time.sleep(0.3)

        t.check(len(received_packets) > 0, "DATA echo received through relay",
                detail=f"received {len(received_packets)} packets")

        # === Phase 3: Link through relay ===
        t._log("=== Phase 3: Link through relay ===")

        link_established = [False]

        def link_established_cb(link):
            t._log("LINK ESTABLISHED through relay")
            link_established[0] = True

        link = RNS.Link(esp32_dest)
        link.set_link_established_callback(link_established_cb)

        deadline = time.time() + 25
        while time.time() < deadline and not link_established[0]:
            time.sleep(0.3)

        t.check(link_established[0], "Link established through relay")

        if link_established[0]:
            # === Phase 4: Channel through relay ===
            t._log("=== Phase 4: Channel messages ===")

            received_channel_msgs = []

            def channel_msg_handler(message):
                t._log(f"CHANNEL_MSG: {message.data!r}")
                received_channel_msgs.append(message.data)

            channel = link.get_channel()
            channel.register_message_type(TestMessage)
            channel.add_message_handler(channel_msg_handler)

            time.sleep(3.0)  # LRRTT stabilization + greeting

            got_greeting = any(b"esp32-hello" in m for m in received_channel_msgs)
            t.check(got_greeting, "ESP32 greeting received through relay",
                    detail=f"received {len(received_channel_msgs)} channel msgs: {received_channel_msgs!r}")

            # Send channel message
            msg = TestMessage(b"relay-diag-msg")
            t._log("Sending channel message: relay-diag-msg")
            channel.send(msg)

            deadline = time.time() + 10
            while time.time() < deadline:
                if any(b"echo:relay-diag-msg" in m for m in received_channel_msgs):
                    break
                time.sleep(0.3)

            got_echo = any(b"echo:relay-diag-msg" in m for m in received_channel_msgs)
            t.check(got_echo, "Channel echo received through relay",
                    detail=f"received {len(received_channel_msgs)} channel msgs: {received_channel_msgs!r}")

            link.teardown()
            time.sleep(2.0)

        # === Dump diagnostics ===
        t._log("=== Diagnostic output ===")

        rust_stderr = t.collect_rust_stderr()
        t.dump_output("Rust stdout", rust_lines)
        t.dump_output("Rust stderr (last 1500)", rust_stderr.strip().split("\n"))
        dump_bridge_stderr(t, bridge)
        dump_proxy_stderr(t, proxy)

        # Cleanup
        RNS.Reticulum.exit_handler()
        import shutil
        shutil.rmtree(py_tmpdir, ignore_errors=True)


def dump_bridge_stderr(t, bridge):
    """Read and dump bridge diagnostic output."""
    t._log("--- Diagnostic bridge packet log ---")
    if bridge and bridge.stderr:
        try:
            import select as sel
            lines = []
            while True:
                ready, _, _ = sel.select([bridge.stderr], [], [], 0.1)
                if not ready:
                    break
                data = bridge.stderr.read(4096)
                if not data:
                    break
                lines.extend(data.decode(errors="replace").split("\n"))
            for line in lines[-100:]:  # last 100 lines
                if line.strip():
                    t._log(f"  [bridge] {line}")
        except Exception as e:
            t._log(f"  (could not read bridge stderr: {e})")


def dump_proxy_stderr(t, proxy):
    """Read and dump TCP proxy diagnostic output."""
    t._log("--- TCP proxy packet log ---")
    if proxy and proxy.stderr:
        try:
            import select as sel
            lines = []
            while True:
                ready, _, _ = sel.select([proxy.stderr], [], [], 0.1)
                if not ready:
                    break
                data = proxy.stderr.read(4096)
                if not data:
                    break
                lines.extend(data.decode(errors="replace").split("\n"))
            for line in lines[-100:]:
                if line.strip():
                    t._log(f"  [proxy] {line}")
        except Exception as e:
            t._log(f"  (could not read proxy stderr: {e})")


if __name__ == "__main__":
    main()
