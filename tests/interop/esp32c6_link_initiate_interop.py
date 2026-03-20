#!/usr/bin/env python3
"""ESP32-C6 link initiation interop — Topology A (rete-linux <-> ESP32 over serial).

Tests ESP32 as link initiator:
1. rete-linux announces with app_data "LINK_ME" via stdin
2. ESP32 firmware detects marker, calls initiate_link()
3. Verify LINK_ESTABLISHED on rete-linux
4. ESP32 sends channel message on establishment
5. Verify channel message received by rete-linux
"""

import sys
import time

from interop_helpers import InteropTest


def main():
    with InteropTest("esp32c6-link-initiate", default_port=0, default_timeout=30.0) as t:
        # Start rete-linux connected to ESP32 over serial
        rust_lines = t.start_rust_serial(
            seed="esp32c6-link-init-test-42",
            extra_args=["--peer-seed", "rete-esp32c6-test"],
        )

        # Wait for rete-linux to start up
        time.sleep(2.0)

        # Send an announce with "LINK_ME" app_data via stdin
        # This triggers ESP32 firmware to initiate a link back to us
        t._log("sending announce with LINK_ME app_data...")
        t.send_rust("announce LINK_ME")

        # Wait for LINK_ESTABLISHED (ESP32 initiates, rete-linux is responder)
        t._log("waiting for ESP32 to initiate link (triggered by LINK_ME)...")
        link_line = t.wait_for_line(rust_lines, "LINK_ESTABLISHED", timeout=20)
        t.check(link_line is not None, "Link established (ESP32 initiated)")

        if link_line is None:
            t.dump_output("Rust stdout", rust_lines)
            return

        # Extract link_id
        link_id = link_line.strip()
        t._log(f"link_id: {link_id}")

        # ESP32 sends "esp32-hello" channel message on link establishment
        time.sleep(3.0)
        got_greeting = t.has_line(rust_lines, "CHANNEL_MSG", contains="esp32-hello")
        t.check(got_greeting, "Received ESP32 greeting channel message after link initiation")

        # Close the link to free ESP32 slot
        t.close_esp32_link(link_id)

        # Dump output
        t.dump_output("Rust stdout", rust_lines)


if __name__ == "__main__":
    main()
