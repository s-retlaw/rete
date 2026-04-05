#!/usr/bin/env python3
"""ESP32-C6 link interop test — Topology A (rete <-> ESP32 over serial).

Tests link handshake with ESP32 as responder:
1. rete initiates link to ESP32 (dest hash discovered via announce)
2. Verify LINK_ESTABLISHED
3. Verify ESP32 sends greeting channel message
4. Send channel message, verify echo
5. Send link data, verify echo
"""

import sys
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("esp32c6-link", default_port=0, default_timeout=30.0) as t:
        # Start rete connected to ESP32 over serial
        rust_lines = t.start_rust_serial()

        # Discover ESP32 destination hash from its announce
        esp32_dest = t.discover_esp32_dest(rust_lines, timeout=15)
        if esp32_dest is None:
            t.check(False, "Discover ESP32 destination hash")
            t.dump_output("Rust stdout", rust_lines)
            return

        # Establish link
        link_id, ok = t.establish_esp32_link(rust_lines, esp32_dest)
        t.check(ok, "Link established with ESP32")
        if not ok:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Wait for ESP32's greeting channel message ("esp32-hello")
        time.sleep(2.0)
        got_greeting = t.has_line(rust_lines, "CHANNEL_MSG", contains="esp32-hello")
        t.check(got_greeting, "Received ESP32 greeting channel message")

        # Send a channel message
        t._log("sending channel message...")
        t.send_rust(f"channel {link_id} 0001 hello-from-linux")

        # Wait for echo
        time.sleep(3.0)
        got_echo = t.has_line(rust_lines, "CHANNEL_MSG", contains="echo:hello-from-linux")
        t.check(got_echo, "Received echoed channel message from ESP32")

        # Send link data
        t._log("sending link data...")
        t.send_rust(f"linkdata {link_id} raw-data-test")

        # Wait for link data echo
        time.sleep(3.0)
        got_data_echo = t.has_line(rust_lines, "LINK_DATA", contains="echo:raw-data-test")
        t.check(got_data_echo, "Received echoed link data from ESP32")

        # Close the link to free ESP32 slot
        t.close_esp32_link(link_id)

        # Dump output for debugging
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
